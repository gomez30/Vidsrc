import httpx
import re
import base64
import hashlib
import time
import os
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class VidsrcExtractor:
    def __init__(self):
        self.base_url = os.getenv("VIDSRC_BASE_URL", "https://vidsrc.cc").rstrip("/")
        proxy_url = os.getenv("UPSTREAM_PROXY_URL")
        self.browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
        }
        self.client = httpx.Client(
            headers={**self.browser_headers, "Referer": f"{self.base_url}/"},
            follow_redirects=True,
            timeout=30.0,
        )
        if proxy_url:
            # Support both old and new httpx proxy keyword styles.
            try:
                self.client = httpx.Client(
                    headers={**self.browser_headers, "Referer": f"{self.base_url}/"},
                    proxies=proxy_url,
                    follow_redirects=True,
                    timeout=30.0,
                )
            except TypeError:
                self.client = httpx.Client(
                    headers={**self.browser_headers, "Referer": f"{self.base_url}/"},
                    proxy=proxy_url,
                    follow_redirects=True,
                    timeout=30.0,
                )
        self.secret_prefix = "Cns#nGelOl"
        self.stream_cache = {}
        self.stream_cache_ttl = 300
        self.token_cache = {}
        self.token_cache_ttl = 900
        self.last_error = None

    def _fail(self, message, upstream_status=None):
        if upstream_status is not None:
            self.last_error = f"{message} (upstream_status={upstream_status})"
        else:
            self.last_error = message
        print(self.last_error)
        return None

    def _extract_streameee_token(self, html):
        xy_ws_match = re.search(r'window\._xy_ws\s*=\s*"([^"]+)"', html)
        if xy_ws_match:
            raw_token = xy_ws_match.group(1)
            return raw_token[:-1] if raw_token.endswith("X") else raw_token

        is_th_match = re.search(r'<!--\s*_is_th:([^\s<]+)\s*-->', html)
        if is_th_match:
            return is_th_match.group(1)

        meta_tag = BeautifulSoup(html, 'html.parser').find('meta', {'name': '_gg_fb'})
        if meta_tag:
            return meta_tag.get('content')

        return None

    def _fetch_streameee_token_http_only(self, url, referer):
        cached = self.token_cache.get(url)
        if cached and cached["expires_at"] > time.time():
            return cached["token"]

        request_profiles = [
            {
                **self.browser_headers,
                "Referer": referer,
                "Sec-Fetch-Dest": "iframe",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site",
            },
            {
                **self.browser_headers,
                "Referer": referer,
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site",
            },
            {
                **self.browser_headers,
                "Referer": url,
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
            },
        ]

        try:
            for headers in request_profiles:
                response = self.client.get(url, headers=headers, follow_redirects=True)
                token = self._extract_streameee_token(response.text)
                if token:
                    self.token_cache[url] = {
                        "token": token,
                        "expires_at": time.time() + self.token_cache_ttl,
                    }
                    return token

            time.sleep(0.15)
            response = self.client.get(url, headers=request_profiles[-1], follow_redirects=True)
            token = self._extract_streameee_token(response.text)
            if token:
                self.token_cache[url] = {
                    "token": token,
                    "expires_at": time.time() + self.token_cache_ttl,
                }
            return token
        except Exception as e:
            print(f"HTTP token fallback failed: {e}")
            return None

    def generate_vrf(self, movie_id, user_id):
        secret = f"{self.secret_prefix}X_{user_id}"
        key = hashlib.sha256(secret.encode("utf-8")).digest()
        
        pad_len = 16 - (len(movie_id) % 16)
        padded_data = movie_id.encode("utf-8") + bytes([pad_len] * pad_len)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(bytes(16)),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        vrf = (
            base64.b64encode(ciphertext)
            .decode("ascii")
            .replace("+", "-")
            .replace("/", "_")
            .rstrip("=")
        )
        return vrf

    def get_stream(self, id, is_tv=False, season=None, episode=None, is_anime=False, sub_or_dub="sub"):
        self.last_error = None
        cache_key = (id, is_tv, season, episode, is_anime, sub_or_dub)
        cached = self.stream_cache.get(cache_key)
        if cached and cached["expires_at"] > time.time():
            return cached["result"]

        if is_anime:
            url = f"{self.base_url}/v2/embed/anime/{id}/{episode}/{sub_or_dub}?autoPlay=false"
        elif is_tv:
            url = f"{self.base_url}/v2/embed/tv/{id}/{season}/{episode}"
        else:
            url = f"{self.base_url}/v2/embed/movie/{id}"

        res = self.client.get(url, headers={
            **self.browser_headers,
            "Referer": f"{self.base_url}/",
        })
        if res.status_code != 200:
            return self._fail("Failed to fetch embed page (possible Cloudflare block or invalid ID)", upstream_status=res.status_code)
            
        soup = BeautifulSoup(res.text, 'html.parser')
        
        try:
            script_tag = soup.find('script', string=re.compile("var v ="))
            if not script_tag:
                return self._fail("Could not find expected player script variables (upstream page likely changed)")
            
            script_text = script_tag.text
            
            def get_var(name, text):
                match = re.search(fr'var {name}\s*=\s*"(.*?)"', text)
                if match: return match.group(1)
                match = re.search(fr'var {name}\s*=\s*([^;]+);', text)
                if match: return match.group(1).strip().strip("'").strip('"')
                return None

            v = get_var("v", script_text)
            user_id = get_var("userId", script_text)
            movie_id = get_var("movieId", script_text) or get_var("malId", script_text) or get_var("anilistId", script_text)
            imdb_id = get_var("imdbId", script_text) or ""
            
            if not all([v, user_id, movie_id]):
                return self._fail("Failed to extract required vars from embed page (v/userId/movieId)")
        except Exception as e:
            return self._fail(f"Error parsing embed page variables: {e}")

        vrf = self.generate_vrf(movie_id, user_id)

        params = {
            "id": movie_id,
            "type": "tv" if is_tv else "movie",
            "v": v,
            "vrf": vrf,
            "imdbId": imdb_id
        }
        if is_anime:
            params["type"] = "anime"
            params["episode"] = episode
        elif is_tv:
            params["type"] = "tv"
            params["season"] = season
            params["episode"] = episode
        else:
            params["type"] = "movie"

        server_url = f"{self.base_url}/api/{movie_id}/servers"
        server_res = self.client.get(server_url, params=params)
        
        if server_res.status_code == 404:
            server_url = f"{self.base_url}/api/episodes/{movie_id}/servers"
            server_res = self.client.get(server_url, params=params)
        
        try:
            servers = server_res.json()
        except Exception as e:
            return self._fail(f"Failed to parse servers JSON: {e}", upstream_status=server_res.status_code)
        
        if not servers.get("success") or not servers.get("data"):
            return self._fail("Servers endpoint returned empty or failed response", upstream_status=server_res.status_code)
            
        try:
            hash = servers["data"][0]["hash"]
        except (IndexError, KeyError, TypeError) as e:
            return self._fail(f"Failed to extract hash from server data: {e}")

        source_res = self.client.get(f"{self.base_url}/api/source/{hash}")
        try:
            source_json = source_res.json()
            if not source_json.get("success") or not source_json.get("data"):
                return self._fail("Source endpoint returned empty or failed response", upstream_status=source_res.status_code)
            iframe_url = source_json["data"]["source"]
        except Exception as e:
            return self._fail(f"Failed to parse source iframe response: {e}", upstream_status=source_res.status_code)

        import urllib.parse
        iframe_url = urllib.parse.unquote(iframe_url)
        iframe_url = urllib.parse.urljoin(self.base_url, iframe_url)
        lucky_res = self.client.get(iframe_url, follow_redirects=True, headers={
            **self.browser_headers,
            "Referer": f"{self.base_url}/",
        })
        next_url_match = re.search(r'var source = "(.*?)"', lucky_res.text)
        if not next_url_match:
            return self._fail("Failed to resolve provider source URL from iframe page")
            
        next_url = next_url_match.group(1).replace(r'\/', '/').replace(r'\u0026', '&')
        next_url = urllib.parse.urljoin(iframe_url, next_url)
        # 6. Fetch final embed page
        embed_res = self.client.get(next_url, headers={
            **self.browser_headers,
            "Referer": iframe_url,
        })
        file_id_match = re.search(r'/e-1/(.*?)\?', next_url)
        if not file_id_match:
            return self._fail("Failed to extract provider file_id from resolved URL")
        file_id = file_id_match.group(1)
            
        base_parts = next_url.split('/embed-')[0]
        embed_id_match = re.search(r'/(embed-\d+)/', next_url)
        if not embed_id_match:
            return self._fail("Failed to extract provider embed_id from resolved URL")
        embed_id = embed_id_match.group(1)
        
        try:
            if "rapid-cloud" in next_url:
                sources_url = f"{base_parts}/{embed_id}/v2/e-1/getSources?id={file_id}"
                final_res = self.client.get(sources_url, headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": next_url
                })
                result = final_res.json()
                self.stream_cache[cache_key] = {
                    "result": result,
                    "expires_at": time.time() + self.stream_cache_ttl,
                }
                return result
            else:
                k_token = self._extract_streameee_token(embed_res.text)

                if not k_token:
                    k_token = self._fetch_streameee_token_http_only(next_url, iframe_url)
                elif next_url not in self.token_cache:
                    self.token_cache[next_url] = {
                        "token": k_token,
                        "expires_at": time.time() + self.token_cache_ttl,
                    }

                if not k_token:
                    return self._fail("Failed to find _k token on provider page (provider anti-bot may have changed)")

                sources_url = f"{base_parts}/{embed_id}/v3/e-1/getSources?id={file_id}&_k={k_token}"
                
                final_res = self.client.get(sources_url, headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": next_url
                })
                result = final_res.json()
                self.stream_cache[cache_key] = {
                    "result": result,
                    "expires_at": time.time() + self.stream_cache_ttl,
                }
                return result
        except Exception as e:
            return self._fail(f"Final extraction failed: {e}")

if __name__ == "__main__":
    extractor = VidsrcExtractor()
    # Test with Fast X (movie)
    print(extractor.get_stream("385687"))
