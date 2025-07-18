 #Web Audit Tool (Python + Playwright + BeautifulSoup)

#This tool audits a given website for:
- SEO Health
- Performance
- Accessibility
- Security
- Mobile friendliness
- Best Practices

It generates a **detailed JSON report (`web_audit_result.json`)** and optionally captures a mobile screenshot (`mobile_view.png`).

------------------------------

-----How to Run------.

 #Run via CLI:
 
   -python `web_audit.py` https://example.com

#If no argument passed

  -python `web_audit.py`


----Requirements---

Python 3.7+  
- Playwright (browser automation)  
- BeautifulSoup4 (HTML parsing)  
- requests (HTTP requests)  
- axe-core CLI (for accessibility)  
- Node.js (axe install)



## Compilation 
 Clone or download the project

Install Python packages: 
pip install  -Playwright 
- BeautifulSoup4
- requests 
- axe-core CLI  
  

 Run playwright install

 Install axe-core CLI via npm

(Optional) Set up virtual environment (recommended)



# ---Design Overview (Design structure)----.

 
 Main driver - `check_url(url)`
 
      - method calls each check sequentially and saves the output as a JSON file.

 SEO  Meta tag - `extract_meta_tags()`
 
     -Checks title, meta description, og:title, and canonical 

  Internal vs External Link - `check_link_ratio()`  
  
    - Counts internal and external links  
    
Broken Links- `find_broken_links()`   

    - Detects 404 or unreachable links 
    
Mobile View Screenshot `check_mobile_view()`   

    - Captures mobile screenshot using Playwright (iPhone 12)

Viewport Meta Tag -`check_viewport_meta()`        

    - Checks for mobile responsive viewport tag     

Performance Metrics -`check_performance_metrics()`   

    - Measures page load timings (FCP, DOM, Load event)  


  Render Blocking JS/CSS - `check_render_blocking()` 
  
     - Detects JS/CSS files that block rendering (no defer/async)

  
 Minified Assets -`check_minified_assets()` 
 
      -Lists JS/CSS files that are not minified      

  
 Lazy Loading -`check_lazy_loading()`   
 
     - Checks if images use `loading="lazy"`     


Accessibility (axe-core) - `run_axe_accessibility_audit()`  

    - Runs WAI-ARIA based accessibility audit using axe-core

Heading Structure- `check_heading_structure()`      

    - Analyzes usage of heading tags (h1 to h6)  

Indexability - `check_indexability()`         

    - Checks for presence of robots.txt and sitemap.xml

 Security Headers -`check_security_headers()`       
 
     - Checks security-related headers like CSP, X-Frame, etc.

Cookie Flags -`check_cookie_flags()`           

    - Checks if cookies use Secure and HttpOnly flags   

Mixed Content -`check_mixed_content()`  

    - Detects HTTP content (images/scripts) on HTTPS pages 

Redirect Chain  - `check_redirect_chain()` 

    - Detects number and list of redirects in a chain  


Large Images - `check_large_images()`        

    - Detects images larger than 300KB    

Content Analysis - `check_content_structure()`     

    - Analyzes word count and most frequent words    
