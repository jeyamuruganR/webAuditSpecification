import re
import sys
import urllib
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import json
import subprocess


class Web_audit:

    def get_html(self, url):
        try:
            return requests.get(url).text
        except:
            return None

    def is_valid_url(self, url):
        regax = r'^https://[a-zA-Z0-9\-\.]+\.[a-z]{2,5}(/.*)?$'
        try:
            if re.match(regax, url) and requests.get(url).status_code == 200:
                return True
            else:
                return False
        except:
            return False

    def extract_meta_tags(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip() if soup.title else "Missing Title"
        description_tag = soup.find("meta", attrs={"name": "description"})
        canonical_tag = soup.find("link", rel="canonical")
        og_title_tag = soup.find("meta", attrs={"property": "og:title"})


        return {
            "Title": title,
            "Meta Description": description_tag["content"].strip() if description_tag and description_tag.get(
                "content") else "Missing Description",
            "Canonical URL": canonical_tag["href"].strip() if canonical_tag and canonical_tag.get(
                "href") else "Missing Canonical",
            "Open Graph Title": og_title_tag["content"].strip() if og_title_tag and og_title_tag.get(
                "content") else "Missing OG Title",

        }

    def check_link_ratio(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        internal = 0
        external = 0
        parsed_base = urlparse(base_url).netloc

        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                continue  # ignore these special cases
            full_url = urljoin(base_url, href)
            parsed_href = urlparse(full_url).netloc

            if parsed_href == parsed_base:
                internal += 1
            else:
                external += 1

        return {
            "Internal Links": internal,
            "External Links": external
        }

    def find_broken_links(self, html, url):
        soup = BeautifulSoup(html, 'html.parser')
        links = [a.get("href") for a in soup.find_all("a")]
        broken_links = []
        total_checked = 0
        print(f"\nTotal links found: {len(links)}")
        for link in links:
            full_url = urljoin(url, link)
            if not full_url.startswith("http"):
                continue
            try:
                response = requests.get(full_url, allow_redirects=True, timeout=3)
                total_checked += 1
                if response.status_code >= 400:
                    broken_links.append((full_url, response.status_code))
            except:
                broken_links.append((full_url, "No response"))
        return broken_links, total_checked

    def check_mobile_view(self, url):
        try:
            with sync_playwright() as p:
                iphone = p.devices["iPhone 12"]
                browser = p.webkit.launch()
                page = browser.new_page(**iphone)
                page.goto(url, timeout=10000)
                page.screenshot(path="mobile_view.png")
                browser.close()
                return " Mobile screenshot saved as mobile_view.png"
        except Exception as e:
            return f" Mobile view check failed: {str(e)}"

    def check_viewport_meta(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        viewport_tag = soup.find("meta", attrs={"name": "viewport"})
        if viewport_tag and viewport_tag.get("content"):
            return f"Viewport tag found: {viewport_tag['content']}"
        return "Missing viewport meta tag"

    def check_performance_metrics(self, url):
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(url, wait_until="load", timeout=10000)
                metrics_json = page.evaluate("() => JSON.stringify(window.performance.timing)")
                browser.close()
                metrics = json.loads(metrics_json)
                navigation_start = metrics["navigationStart"]
                fcp = metrics["responseStart"] - navigation_start
                dom_complete = metrics["domComplete"] - navigation_start
                load_event = metrics["loadEventEnd"] - navigation_start
                return {
                    "First Byte Time (FCP)": f"{fcp} ms",
                    "DOM Complete Time": f"{dom_complete} ms",
                    "Total Load Time": f"{load_event} ms"
                }
        except Exception as e:
            return {"Performance Error": str(e)}

    def check_render_blocking(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        blocking_scripts = []
        blocking_css = []

        for script in soup.find_all("script", src=True):
            if not script.has_attr("async") and not script.has_attr("defer"):
                blocking_scripts.append(script["src"])

        for link in soup.find_all("link", rel="stylesheet"):
            if link.has_attr("href"):
                blocking_css.append(link["href"])

        return {
            "Blocking JS": blocking_scripts if blocking_scripts else "None",
            "Blocking CSS": blocking_css if blocking_css else "None"
        }

    def check_minified_assets(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        unminified_files = []

        links = soup.find_all(['script', 'link'])

        for tag in links:
            if tag.name == 'script' and tag.get('src'):
                url = urljoin(base_url, tag['src'])
            elif tag.name == 'link' and tag.get('rel') == ['stylesheet'] and tag.get('href'):
                url = urljoin(base_url, tag['href'])
            else:
                continue

            if ".min." in url:
                continue  # already minified
            try:
                res = requests.get(url, timeout=5)
                if res.status_code == 200 and res.text.count("\n") > 50:
                    unminified_files.append(url)
            except:
                continue

        return unminified_files

    def check_lazy_loading(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        images = soup.find_all("img")
        non_lazy_images = []

        for img in images:
            if not img.has_attr("loading") or img["loading"] != "lazy":
                src = img.get("src", "unknown")
                non_lazy_images.append(src)

        return {
            "Total Images": len(images),
            "Non-Lazy Images": non_lazy_images if non_lazy_images else "All images use lazy loading"
        }

    def check_security_headers(self, url):
        try:
            response = requests.get(url)
            headers = response.headers
            return {
                "CSP": headers.get("Content-Security-Policy", "Missing"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
                "CORS (Access-Control-Allow-Origin)": headers.get("Access-Control-Allow-Origin", "Missing")
            }
        except Exception as e:
            return {"Security Header Error": str(e)}

    def check_indexability(self, url):
        try:
            base = urlparse(url).scheme + "://" + urlparse(url).netloc
            robots_url = urljoin(base, "/robots.txt")
            sitemap_url = urljoin(base, "/sitemap.xml")
            robots_response = requests.get(robots_url)
            sitemap_response = requests.get(sitemap_url)
            return {
                "robots.txt Present": "Ok" if robots_response.status_code == 200 else "Missing",
                "sitemap.xml Present": "OK" if sitemap_response.status_code == 200 else "Missing",
            }
        except Exception as e:
            return {"Indexability Error": str(e)}

    def check_heading_structure(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        headings = [(tag.name, tag.get_text(strip=True)) for tag in soup.find_all(re.compile('^h[1-6]$'))]
        return {
            "Total Headings Found": len(headings),
            "Headings List": headings
        }

    def check_cookie_flags(self, url):
        try:
            response = requests.get(url)
            cookies = response.cookies
            result = []
            for cookie in cookies:
                result.append({
                    "Name": cookie.name,
                    "Secure": cookie.secure,
                    "HttpOnly": cookie.has_nonstandard_attr("HttpOnly")
                })
            return result if result else "No cookies found"
        except Exception as e:
            return {"Cookie Check Error": str(e)}

    def check_mixed_content(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        mixed_content = []

        tags_attrs = {
            "img": "src",
            "script": "src",
            "link": "href",
            "iframe": "src",
            "video": "src",
            "audio": "src",
            "source": "src"
        }

        for tag, attr in tags_attrs.items():
            for element in soup.find_all(tag):
                src = element.get(attr)
                if src and src.startswith("http://"):
                    full_url = urljoin(base_url, src)
                    mixed_content.append(full_url)

        return mixed_content if mixed_content else "No mixed content found"

    def check_redirect_chain(self, url):
        try:
            response = requests.get(url, allow_redirects=True)
            chain = [resp.url for resp in response.history] + [response.url]
            if len(chain) > 1:
                return {
                    "Redirect Chain Count": len(chain) - 1,
                    "Redirect Chain": chain
                }
            else:
                return "No redirects found"
        except Exception as e:
            return {"Redirect Error": str(e)}

    def check_large_images(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        images = soup.find_all("img")
        large_images = []
        for img in images:
            src = img.get("src")
            if not src:
                continue
            full_url = urljoin(base_url, src)
            try:
                res = requests.get(full_url, stream=True, timeout=3)
                size_kb = int(res.headers.get("Content-Length", 0)) // 1024
                if size_kb > 300:
                    large_images.append((full_url, f"{size_kb} KB"))
            except:
                continue
        return large_images

    def check_content_structure(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        paragraphs = soup.find_all('p')
        full_text = " ".join([p.get_text() for p in paragraphs])
        words = full_text.split()
        word_count = len(words)
        from collections import Counter
        word_freq = Counter(words)
        common_words = word_freq.most_common(5)
        return {
            "Total Word Count": word_count,
            "Top 5 Repeated Words": common_words
        }

    def run_axe_accessibility_audit(self, url):
        try:
            output_file = "axe_report.json"
            cmd = ["axe", url, "--save", output_file]
            subprocess.run(cmd, check=True)

            with open(output_file, "r", encoding="utf-8") as f:
                report = json.load(f)

            violations = report.get("violations", [])
            if not violations:
                return " No accessibility issues found"

            results = []
            for issue in violations:
                results.append(f" {issue['help']} (Impact: {issue.get('impact', 'N/A')})")
            return results
        except Exception as e:
            return [f" Accessibility audit failed: {str(e)}"]

    def check_url(self, url):
        if self.is_valid_url(url):
            print("--------------------------------------")
            print(" URL is valid. Fetching HTML content...")
            audit_result = {}
            audit_result["URL Status"] = "Valid"

            html = self.get_html(url)

            print("--------------------------------------")
            print("SEO Meta Tags...")
            meta = self.extract_meta_tags(html)
            audit_result["Meta Tags"] = meta
            for k, v in meta.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print(" Internal vs External Link Balance...")
            link_balance = self.check_link_ratio(html, url)
            audit_result["Link Balance"] = link_balance
            for k, v in link_balance.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print(" Checking Broken Links...")
            broken_links, total_checked = self.find_broken_links(html, url)
            audit_result["Broken Links Checked"] = total_checked
            audit_result["Broken Links"] = broken_links
            print(f"Total links checked: {total_checked}")
            if broken_links:
                for link, code in broken_links:
                    print(f"{link}: {code}")
            else:
                print(" No broken links found")

            print("--------------------------------------")
            print(" Mobile Friendliness...")
            mobile_result = self.check_mobile_view(url)
            audit_result["Mobile View"] = mobile_result
            print(mobile_result)

            viewport_check = self.check_viewport_meta(html)
            audit_result["Viewport Meta"] = viewport_check
            print("--------------------------------------")
            print(" Viewport Meta Tag...")
            print(viewport_check)

            print("--------------------------------------")
            print(" Performance Metrics...")
            perf = self.check_performance_metrics(url)
            audit_result["Performance"] = perf
            for k, v in perf.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print(" Render Blocking JS/CSS Check...")
            render_blocking = self.check_render_blocking(html)
            audit_result["Render Blocking"] = render_blocking
            print(render_blocking)

            print("--------------------------------------")
            print(" Minified JS/CSS Check...")
            unminified = self.check_minified_assets(html, url)
            audit_result["Unminified Assets"] = unminified
            if unminified:
                for asset in unminified:
                    print(f"Unminified file: {asset}")
            else:
                print(" All JS/CSS are minified")

            print("--------------------------------------")
            print(" Lazy Loading Check...")
            lazy_result = self.check_lazy_loading(html)
            audit_result["Lazy Loading"] = lazy_result
            print(lazy_result)

            print("--------------------------------------")
            print("Heading Structure...")
            heading_info = self.check_heading_structure(html)
            audit_result["Headings"] = heading_info
            for h in heading_info["Headings List"]:
                print(f"{h[0]}: {h[1]}")

            print("--------------------------------------")
            print("Indexability...")
            index_info = self.check_indexability(url)
            audit_result["Indexability"] = index_info
            for k, v in index_info.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print("Security Headers...")
            security = self.check_security_headers(url)
            audit_result["Security Headers"] = security
            for k, v in security.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print("Cookie Flags...")
            cookies = self.check_cookie_flags(url)
            audit_result["Cookies"] = cookies
            if isinstance(cookies, list):
                for c in cookies:
                    print(f"{c['Name']} - Secure: {c['Secure']} | HttpOnly: {c['HttpOnly']}")
            else:
                print(cookies)

            print("--------------------------------------")
            print(" Mixed Content Check...")
            mixed = self.check_mixed_content(html, url)
            audit_result["Mixed Content"] = mixed
            if isinstance(mixed, list):
                for item in mixed:
                    print(f"Mixed content: {item}")
            else:
                print(mixed)

            print("--------------------------------------")
            print(" Redirect Chain Check...")
            redirects = self.check_redirect_chain(url)
            audit_result["Redirects"] = redirects
            print(redirects)

            print("--------------------------------------")
            print("Large Image Optimization Check...")
            large_imgs = self.check_large_images(html, url)
            audit_result["Large Images"] = large_imgs
            if large_imgs:
                for img, size in large_imgs:
                    print(f" {img} is large: {size}")
            else:
                print(" No oversized images found.")

            print("--------------------------------------")
            print("Content Structure Analysis...")
            structure_info = self.check_content_structure(html)
            audit_result["Content Structure"] = structure_info
            for k, v in structure_info.items():
                print(f"{k}: {v}")

            print("--------------------------------------")
            print("Accessibility Check (axe-core)...")
            axe_results = self.run_axe_accessibility_audit(url)
            audit_result["Accessibility"] = axe_results
            if isinstance(axe_results, list):
                for line in axe_results:
                    print(line)
            else:
                print(axe_results)

            print("--------------------------------------")
            print(" Saving JSON report as web_audit_result.json ...")
            with open("web_audit_result.json", "w", encoding="utf-8") as f:
                json.dump(audit_result, f, indent=4, ensure_ascii=False)

            return "Audit Completed and JSON file saved as web_audit_result.json"

        else:
            return " Invalid URL"




if __name__ == "__main__":
    web_audit = Web_audit()
    if len(sys.argv) < 2:
        input_url = input("Enter the URL to check: ").strip()
    else:
        input_url = sys.argv[1]

    result = web_audit.check_url(input_url)
    print(result)

