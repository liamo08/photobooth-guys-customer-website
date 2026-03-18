"""
SEO Analyzer module for Photobooth Guys admin panel.
Performs technical SEO crawl on static HTML files and generates recommendations.
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path


# Prompt templates for Claude Code recommendations
PROMPTS = {
    "missing_title": (
        'In the file {filepath}, add a <title> tag inside the <head> section. '
        'The title should be 50-60 characters, include the primary keyword for this page, '
        'mention "Ireland" where relevant, and follow the format: '
        '"Primary Keyword | Photobooth Guys". Do not modify any other part of the file.'
    ),
    "title_length": (
        'In the file {filepath}, update the <title> tag. The current title is {current_length} characters: '
        '"{current_value}". Rewrite it to be 50-60 characters while keeping the primary keyword '
        'and "Photobooth Guys" branding. Do not modify any other part of the file.'
    ),
    "missing_meta_desc": (
        'In the file {filepath}, add a <meta name="description" content="..."> tag inside the <head> section, '
        'directly after the <title> tag. Write a compelling meta description that is 150-160 characters long, '
        'naturally includes the primary keyword for this page, mentions Ireland where relevant, '
        'and ends with a call to action. Do not modify any other part of the file.'
    ),
    "meta_desc_length": (
        'In the file {filepath}, update the <meta name="description"> tag. The current description is '
        '{current_length} characters: "{current_value}". Rewrite it to be 150-160 characters while keeping '
        'the primary keyword and a call to action. Do not modify any other part of the file.'
    ),
    "missing_h1": (
        'In the file {filepath}, there is no <h1> tag. Add exactly one <h1> tag containing the '
        'primary keyword for this page. Place it as the first heading in the main content area. '
        'Do not modify any other part of the file.'
    ),
    "multiple_h1": (
        'In the file {filepath}, there are {count} H1 tags. There should be exactly one. '
        'Keep the most relevant H1 and convert the others to <h2> tags. '
        'Do not change page styling or layout.'
    ),
    "missing_canonical": (
        'In the file {filepath}, add a <link rel="canonical" href="https://www.photoboothguys.ie/{page_path}"> '
        'tag inside the <head> section. Do not modify any other part of the file.'
    ),
    "missing_og_tags": (
        'In the file {filepath}, add Open Graph meta tags inside the <head> section: '
        'og:title (same as <title>), og:description (same as meta description), '
        'og:image (use the hero image from the page or /logo.webp), '
        'og:url (canonical URL), and og:type (website). Do not modify any other part of the file.'
    ),
    "low_word_count": (
        'The page {filepath} has only {word_count} words of content. For better SEO rankings, '
        'add more relevant content to bring the total to at least 500 words. Add sections that cover '
        'related topics, benefits, process details, or FAQs relevant to the page subject. '
        'Maintain the existing page structure and design.'
    ),
    "missing_alt_text": (
        'In the file {filepath}, there are {count} images missing alt text. '
        'Add descriptive, keyword-rich alt text to each <img> tag that is missing it. '
        'Alt text should describe the image content and naturally include relevant keywords. '
        'Do not modify any other attributes or parts of the file.'
    ),
    "invalid_json_ld": (
        'In the file {filepath}, the JSON-LD structured data (inside <script type="application/ld+json">) '
        'contains invalid JSON. Fix the JSON syntax errors while keeping the schema content intact. '
        'Validate that the JSON is well-formed after fixing.'
    ),
    "missing_json_ld": (
        'In the file {filepath}, add a JSON-LD structured data block inside the <head> section. '
        'Use the appropriate schema type for this page (LocalBusiness for the homepage, '
        'Service for service pages, Article for blog posts, FAQPage for FAQ sections). '
        'Include the business name "Photobooth Guys", location "Ireland", and relevant page details.'
    ),
    "keyword_opportunity": (
        'The page {filepath} ranks at position {position} for "{keyword}" with {impressions} '
        'monthly impressions but only {clicks} clicks. Improve the ranking by: '
        '1) Ensuring "{keyword}" appears in the title tag, H1, and first paragraph. '
        '2) Adding a dedicated section of 200-300 words about this topic. '
        '3) Adding an FAQ question about "{keyword}" with schema markup. '
        'Do not remove existing content.'
    ),
    "ctr_improvement": (
        'The page {filepath} ranks at position {position} for "{keyword}" but has a low CTR of {ctr}%. '
        'Improve click-through rate by: 1) Making the title tag more compelling with a value proposition. '
        '2) Rewriting the meta description with a clear call to action and unique selling points. '
        '3) Consider adding FAQ schema to get rich snippets in search results.'
    ),
}


def run_technical_crawl(base_dir):
    """Crawl all HTML files and check for technical SEO issues."""
    base = Path(base_dir)
    results = []
    html_files = []

    for pattern_dir in ["", "services", "locations", "blog"]:
        search_dir = base / pattern_dir if pattern_dir else base
        if search_dir.exists():
            for f in search_dir.glob("*.html"):
                rel = str(f.relative_to(base))
                if not rel.startswith("admin"):
                    html_files.append((rel, f))

    all_pages = {rel for rel, _ in html_files}

    for rel_path, filepath in html_files:
        html = filepath.read_text(errors="replace")
        page_issues = analyze_page(rel_path, html, all_pages)
        if page_issues:
            results.append({
                "page": rel_path,
                "page_url": "/" + rel_path.replace(".html", ""),
                "issues": page_issues,
            })

    return results


def analyze_page(rel_path, html, all_pages):
    """Analyze a single HTML page for SEO issues."""
    issues = []

    # Extract head content
    head_match = re.search(r"<head[^>]*>(.*?)</head>", html, re.DOTALL | re.IGNORECASE)
    head = head_match.group(1) if head_match else ""

    # Extract body content
    body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.DOTALL | re.IGNORECASE)
    body = body_match.group(1) if body_match else html

    # 1. Title tag
    title_match = re.search(r"<title[^>]*>(.*?)</title>", head, re.DOTALL | re.IGNORECASE)
    if not title_match:
        issues.append({
            "check": "title",
            "severity": "critical",
            "message": "Missing <title> tag",
            "prompt_key": "missing_title",
            "prompt_vars": {"filepath": rel_path},
        })
    else:
        title_text = title_match.group(1).strip()
        title_len = len(title_text)
        if title_len < 30 or title_len > 65:
            issues.append({
                "check": "title_length",
                "severity": "medium",
                "message": f"Title tag is {title_len} chars (optimal: 50-60)",
                "prompt_key": "title_length",
                "prompt_vars": {
                    "filepath": rel_path,
                    "current_length": title_len,
                    "current_value": title_text[:80],
                },
            })

    # 2. Meta description
    desc_match = re.search(
        r'<meta\s+name="description"\s+content="([^"]*)"',
        head, re.IGNORECASE
    )
    if not desc_match:
        desc_match = re.search(
            r"<meta\s+name='description'\s+content='([^']*)'",
            head, re.IGNORECASE
        )
    if not desc_match:
        desc_match = re.search(
            r'<meta\s+content="([^"]*)"\s+name="description"',
            head, re.IGNORECASE
        )
    if not desc_match:
        issues.append({
            "check": "meta_description",
            "severity": "critical",
            "message": "Missing meta description",
            "prompt_key": "missing_meta_desc",
            "prompt_vars": {"filepath": rel_path},
        })
    else:
        desc_text = desc_match.group(1).strip()
        desc_len = len(desc_text)
        if desc_len < 120 or desc_len > 165:
            issues.append({
                "check": "meta_desc_length",
                "severity": "medium",
                "message": f"Meta description is {desc_len} chars (optimal: 120-160)",
                "prompt_key": "meta_desc_length",
                "prompt_vars": {
                    "filepath": rel_path,
                    "current_length": desc_len,
                    "current_value": desc_text[:100],
                },
            })

    # 3. H1 tags
    h1_matches = re.findall(r"<h1[^>]*>(.*?)</h1>", body, re.DOTALL | re.IGNORECASE)
    if len(h1_matches) == 0:
        issues.append({
            "check": "h1",
            "severity": "high",
            "message": "No H1 tag found",
            "prompt_key": "missing_h1",
            "prompt_vars": {"filepath": rel_path},
        })
    elif len(h1_matches) > 1:
        issues.append({
            "check": "h1_multiple",
            "severity": "medium",
            "message": f"Multiple H1 tags found ({len(h1_matches)})",
            "prompt_key": "multiple_h1",
            "prompt_vars": {"filepath": rel_path, "count": len(h1_matches)},
        })

    # 4. Canonical tag
    canonical_match = re.search(r'<link[^>]+rel=["\']canonical["\']', head, re.IGNORECASE)
    if not canonical_match:
        page_path = rel_path.replace(".html", "")
        issues.append({
            "check": "canonical",
            "severity": "medium",
            "message": "Missing canonical tag",
            "prompt_key": "missing_canonical",
            "prompt_vars": {"filepath": rel_path, "page_path": page_path},
        })

    # 5. Open Graph tags
    og_title = re.search(r'<meta\s+property=["\']og:title["\']', head, re.IGNORECASE)
    og_desc = re.search(r'<meta\s+property=["\']og:description["\']', head, re.IGNORECASE)
    og_image = re.search(r'<meta\s+property=["\']og:image["\']', head, re.IGNORECASE)
    missing_og = []
    if not og_title:
        missing_og.append("og:title")
    if not og_desc:
        missing_og.append("og:description")
    if not og_image:
        missing_og.append("og:image")
    if missing_og:
        issues.append({
            "check": "open_graph",
            "severity": "low",
            "message": f"Missing Open Graph tags: {', '.join(missing_og)}",
            "prompt_key": "missing_og_tags",
            "prompt_vars": {"filepath": rel_path},
        })

    # 6. JSON-LD structured data
    json_ld_matches = re.findall(
        r'<script\s+type=["\']application/ld\+json["\']\s*>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE
    )
    if not json_ld_matches:
        issues.append({
            "check": "json_ld",
            "severity": "medium",
            "message": "No JSON-LD structured data found",
            "prompt_key": "missing_json_ld",
            "prompt_vars": {"filepath": rel_path},
        })
    else:
        for i, jld in enumerate(json_ld_matches):
            try:
                json.loads(jld)
            except json.JSONDecodeError:
                issues.append({
                    "check": "json_ld_invalid",
                    "severity": "high",
                    "message": f"Invalid JSON in JSON-LD block {i + 1}",
                    "prompt_key": "invalid_json_ld",
                    "prompt_vars": {"filepath": rel_path},
                })

    # 7. Image alt text
    img_tags = re.findall(r"<img\s[^>]*>", body, re.IGNORECASE)
    missing_alt_count = 0
    for img in img_tags:
        alt_match = re.search(r'alt=["\']([^"\']*)["\']', img, re.IGNORECASE)
        if not alt_match or not alt_match.group(1).strip():
            missing_alt_count += 1
    if missing_alt_count > 0:
        issues.append({
            "check": "alt_text",
            "severity": "medium",
            "message": f"{missing_alt_count} image(s) missing alt text",
            "prompt_key": "missing_alt_text",
            "prompt_vars": {"filepath": rel_path, "count": missing_alt_count},
        })

    # 8. Word count (body text, strip HTML tags)
    text_only = re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.DOTALL | re.IGNORECASE)
    text_only = re.sub(r"<style[^>]*>.*?</style>", "", text_only, flags=re.DOTALL | re.IGNORECASE)
    text_only = re.sub(r"<[^>]+>", " ", text_only)
    text_only = re.sub(r"\s+", " ", text_only).strip()
    word_count = len(text_only.split())
    if word_count < 300:
        issues.append({
            "check": "word_count",
            "severity": "medium",
            "message": f"Low word count: {word_count} words (aim for 500+)",
            "prompt_key": "low_word_count",
            "prompt_vars": {"filepath": rel_path, "word_count": word_count},
        })

    # 9. Internal broken links
    href_matches = re.findall(r'href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE)
    for href in href_matches:
        if href.startswith(("http", "mailto:", "tel:", "javascript:", "//", "{")):
            continue
        clean = href.lstrip("/").split("?")[0].split("#")[0]
        if not clean or clean.startswith("admin"):
            continue
        if clean.endswith(".html") and clean not in all_pages:
            issues.append({
                "check": "broken_link",
                "severity": "high",
                "message": f"Possibly broken internal link: {href}",
                "prompt_key": None,
                "prompt_vars": {},
            })

    # 10. Page file size
    file_size = len(html.encode("utf-8"))
    if file_size > 100_000:
        issues.append({
            "check": "file_size",
            "severity": "low",
            "message": f"Large HTML file: {file_size // 1024}KB (consider splitting)",
            "prompt_key": None,
            "prompt_vars": {},
        })

    return issues


def build_recommendations(technical_results, keywords_data=None):
    """Build actionable recommendation objects from analysis results."""
    recommendations = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # Group issues by type across pages
    issue_groups = {}
    for page_result in technical_results:
        for issue in page_result["issues"]:
            key = issue["check"]
            if key not in issue_groups:
                issue_groups[key] = {
                    "check": key,
                    "severity": issue["severity"],
                    "pages": [],
                    "issues": [],
                }
            issue_groups[key]["pages"].append(page_result["page"])
            issue_groups[key]["issues"].append(issue)

    # Build recommendations from grouped issues
    for key, group in issue_groups.items():
        pages = group["pages"]
        first_issue = group["issues"][0]
        severity = group["severity"]

        if len(pages) == 1:
            title = first_issue["message"]
            description = f"Page: /{pages[0].replace('.html', '')}"
        else:
            title = f"{first_issue['message'].split(':')[0]} on {len(pages)} pages"
            description = "Pages: " + ", ".join(
                f"/{p.replace('.html', '')}" for p in pages[:5]
            )
            if len(pages) > 5:
                description += f" (+{len(pages) - 5} more)"

        # Build the Claude prompt
        claude_prompt = None
        if first_issue.get("prompt_key") and first_issue["prompt_key"] in PROMPTS:
            if len(pages) == 1:
                claude_prompt = PROMPTS[first_issue["prompt_key"]].format(
                    **first_issue["prompt_vars"]
                )
            else:
                prompts = []
                for issue in group["issues"]:
                    if issue.get("prompt_key") and issue["prompt_key"] in PROMPTS:
                        prompts.append(
                            PROMPTS[issue["prompt_key"]].format(**issue["prompt_vars"])
                        )
                claude_prompt = "\n\n".join(prompts)

        recommendations.append({
            "id": f"rec_{key}_{len(pages)}",
            "category": _categorize_check(key),
            "severity": severity,
            "title": title,
            "description": description,
            "affected_pages": pages,
            "claude_prompt": claude_prompt,
        })

    # Add keyword-based recommendations if available
    if keywords_data:
        for kw in keywords_data:
            if 5 <= kw.get("position", 0) <= 20 and kw.get("impressions", 0) > 50:
                page = kw.get("page", "")
                keyword = kw.get("keyword", "")
                recommendations.append({
                    "id": f"rec_kw_{keyword[:20]}",
                    "category": "keywords",
                    "severity": "high" if kw["position"] <= 10 else "medium",
                    "title": f'Keyword opportunity: "{keyword}" (position {kw["position"]:.0f})',
                    "description": (
                        f'{kw["impressions"]} impressions, {kw["clicks"]} clicks, '
                        f'{kw.get("ctr", 0) * 100:.1f}% CTR'
                    ),
                    "affected_pages": [page] if page else [],
                    "claude_prompt": PROMPTS["keyword_opportunity"].format(
                        filepath=page,
                        position=f'{kw["position"]:.0f}',
                        keyword=keyword,
                        impressions=kw["impressions"],
                        clicks=kw["clicks"],
                    ) if page else None,
                })
            if kw.get("position", 0) <= 5 and kw.get("ctr", 0) < 0.05 and kw.get("impressions", 0) > 20:
                page = kw.get("page", "")
                keyword = kw.get("keyword", "")
                recommendations.append({
                    "id": f"rec_ctr_{keyword[:20]}",
                    "category": "keywords",
                    "severity": "medium",
                    "title": f'Low CTR for "{keyword}" (position {kw["position"]:.0f}, {kw.get("ctr", 0) * 100:.1f}% CTR)',
                    "description": f'{kw["impressions"]} impressions but only {kw["clicks"]} clicks',
                    "affected_pages": [page] if page else [],
                    "claude_prompt": PROMPTS["ctr_improvement"].format(
                        filepath=page,
                        position=f'{kw["position"]:.0f}',
                        keyword=keyword,
                        ctr=f'{kw.get("ctr", 0) * 100:.1f}',
                    ) if page else None,
                })

    # Sort by severity
    recommendations.sort(key=lambda r: severity_order.get(r["severity"], 99))
    return recommendations


def calculate_score(technical_results):
    """Calculate an overall SEO score from 0-100."""
    if not technical_results:
        return 100

    total_pages = len(technical_results)
    severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_deductions = 0

    all_issues = []
    for page_result in technical_results:
        all_issues.extend(page_result["issues"])

    for issue in all_issues:
        total_deductions += severity_weights.get(issue["severity"], 1)

    max_possible_deductions = total_pages * 30
    if max_possible_deductions == 0:
        return 100

    score = max(0, 100 - int((total_deductions / max_possible_deductions) * 100))
    return score


def get_git_changes(base_dir, since_days=30):
    """Get recent git commits that touch HTML files."""
    try:
        result = subprocess.run(
            [
                "git", "log",
                f"--since={since_days} days ago",
                "--pretty=format:%H|%aI|%s",
                "--name-only",
                "--diff-filter=ACDMR",
                "--", "*.html",
            ],
            capture_output=True, text=True, cwd=base_dir, timeout=10,
        )
        if result.returncode != 0:
            return []

        changes = []
        current = None
        for line in result.stdout.strip().split("\n"):
            if not line:
                if current:
                    changes.append(current)
                    current = None
                continue
            if "|" in line and line.count("|") >= 2:
                parts = line.split("|", 2)
                current = {
                    "commit_hash": parts[0],
                    "commit_date": parts[1],
                    "commit_message": parts[2],
                    "files_changed": [],
                }
            elif current and line.strip():
                current["files_changed"].append(line.strip())

        if current:
            changes.append(current)

        return changes
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def get_file_at_commit(base_dir, commit_hash, file_path):
    """Get the content of a file at a specific git commit (before the change)."""
    try:
        result = subprocess.run(
            ["git", "show", f"{commit_hash}~1:{file_path}"],
            capture_output=True, text=True, cwd=base_dir, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def run_full_analysis(base_dir, gsc_credentials=None):
    """Run a complete SEO analysis and return the full report."""
    technical_results = run_technical_crawl(base_dir)

    keywords_data = None
    if gsc_credentials:
        keywords_data = fetch_gsc_data(gsc_credentials)

    recommendations = build_recommendations(technical_results, keywords_data)
    score = calculate_score(technical_results)

    # Count issues by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for page_result in technical_results:
        for issue in page_result["issues"]:
            severity_counts[issue["severity"]] = severity_counts.get(issue["severity"], 0) + 1

    summary = {
        "overall_score": score,
        "total_pages_scanned": sum(1 for _ in _iter_html_files(base_dir)),
        "pages_with_issues": len(technical_results),
        "severity_counts": severity_counts,
        "total_issues": sum(severity_counts.values()),
    }

    return {
        "summary": summary,
        "technical": technical_results,
        "keywords": keywords_data,
        "recommendations": recommendations,
        "score": score,
    }


def fetch_gsc_data(credentials):
    """Fetch keyword data from Google Search Console API."""
    try:
        from googleapiclient.discovery import build as build_service
        from datetime import datetime, timedelta

        service = build_service("searchconsole", "v1", credentials=credentials)

        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=28)).strftime("%Y-%m-%d")

        response = service.searchanalytics().query(
            siteUrl="sc-domain:photoboothguys.ie",
            body={
                "startDate": start_date,
                "endDate": end_date,
                "dimensions": ["query", "page"],
                "rowLimit": 500,
            },
        ).execute()

        keywords = []
        for row in response.get("rows", []):
            keys = row.get("keys", [])
            keywords.append({
                "keyword": keys[0] if len(keys) > 0 else "",
                "page": keys[1] if len(keys) > 1 else "",
                "clicks": row.get("clicks", 0),
                "impressions": row.get("impressions", 0),
                "ctr": row.get("ctr", 0),
                "position": row.get("position", 0),
            })

        keywords.sort(key=lambda k: k["impressions"], reverse=True)
        return keywords
    except Exception:
        return None


def _categorize_check(check_name):
    """Map a check name to a category."""
    categories = {
        "title": "technical",
        "title_length": "technical",
        "meta_description": "technical",
        "meta_desc_length": "technical",
        "h1": "technical",
        "h1_multiple": "technical",
        "canonical": "technical",
        "open_graph": "technical",
        "json_ld": "technical",
        "json_ld_invalid": "technical",
        "alt_text": "technical",
        "broken_link": "technical",
        "file_size": "performance",
        "word_count": "content",
    }
    return categories.get(check_name, "technical")


def _iter_html_files(base_dir):
    """Iterate over all public HTML files."""
    base = Path(base_dir)
    for pattern_dir in ["", "services", "locations", "blog"]:
        search_dir = base / pattern_dir if pattern_dir else base
        if search_dir.exists():
            for f in search_dir.glob("*.html"):
                rel = str(f.relative_to(base))
                if not rel.startswith("admin"):
                    yield rel


# ── Serper.dev SERP Analysis ─────────────────────────────────────

def fetch_serp_data(keyword, api_key, location="Dublin, Ireland", gl="ie"):
    """Fetch live SERP results from Serper.dev for a keyword."""
    if not api_key:
        return None
    try:
        payload = json.dumps({
            "q": keyword,
            "gl": gl,
            "location": location,
            "num": 20,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://google.serper.dev/search",
            data=payload,
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        results = {
            "keyword": keyword,
            "location": location,
            "organic": [],
            "local_pack": [],
            "people_also_ask": [],
            "our_position": None,
            "our_url": None,
        }

        for i, item in enumerate(data.get("organic", []), 1):
            entry = {
                "position": i,
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "domain": _extract_domain(item.get("link", "")),
            }
            results["organic"].append(entry)
            if "photoboothguys.ie" in entry.get("link", ""):
                results["our_position"] = i
                results["our_url"] = entry["link"]

        for item in data.get("places", []):
            results["local_pack"].append({
                "title": item.get("title", ""),
                "address": item.get("address", ""),
                "rating": item.get("rating"),
                "reviews": item.get("ratingCount"),
            })

        for item in data.get("peopleAlsoAsk", []):
            results["people_also_ask"].append(item.get("question", ""))

        return results
    except Exception as e:
        return {"error": str(e)}


def _extract_domain(url):
    """Extract domain from a URL."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.replace("www.", "")
    except Exception:
        return url


# ── Google PageSpeed Insights ────────────────────────────────────

def fetch_pagespeed_data(url, api_key=None, strategy="mobile"):
    """Fetch Core Web Vitals and SEO audit from PageSpeed Insights API."""
    params = {
        "url": url,
        "strategy": strategy,
        "category": ["performance", "seo", "accessibility", "best-practices"],
    }
    api_url = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?"
    # Build query string (category appears multiple times)
    qs_parts = [
        f"url={urllib.parse.quote(url, safe='')}",
        f"strategy={strategy}",
        "category=performance",
        "category=seo",
        "category=accessibility",
        "category=best-practices",
    ]
    if api_key:
        qs_parts.append(f"key={api_key}")
    api_url += "&".join(qs_parts)

    try:
        req = urllib.request.Request(api_url, method="GET")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        result = {
            "url": url,
            "strategy": strategy,
            "scores": {},
            "core_web_vitals": {},
            "seo_audits": [],
            "opportunities": [],
        }

        # Category scores (0-100)
        categories = data.get("lighthouseResult", {}).get("categories", {})
        for cat_key, cat_data in categories.items():
            result["scores"][cat_key] = int((cat_data.get("score", 0) or 0) * 100)

        # Core Web Vitals from field data (CrUX)
        field = data.get("loadingExperience", {}).get("metrics", {})
        vitals_map = {
            "LARGEST_CONTENTFUL_PAINT_MS": "LCP",
            "CUMULATIVE_LAYOUT_SHIFT_SCORE": "CLS",
            "INTERACTION_TO_NEXT_PAINT": "INP",
            "FIRST_CONTENTFUL_PAINT_MS": "FCP",
            "EXPERIMENTAL_TIME_TO_FIRST_BYTE": "TTFB",
        }
        for api_name, display_name in vitals_map.items():
            metric = field.get(api_name, {})
            if metric:
                pctile = metric.get("percentile")
                category = metric.get("category", "").lower()
                result["core_web_vitals"][display_name] = {
                    "value": pctile,
                    "rating": category,
                }

        # If no field data, fall back to lab data
        if not result["core_web_vitals"]:
            audits = data.get("lighthouseResult", {}).get("audits", {})
            lab_map = {
                "largest-contentful-paint": "LCP",
                "cumulative-layout-shift": "CLS",
                "interactive": "TTI",
                "first-contentful-paint": "FCP",
                "speed-index": "Speed Index",
                "total-blocking-time": "TBT",
            }
            for audit_id, display_name in lab_map.items():
                audit = audits.get(audit_id, {})
                if audit:
                    result["core_web_vitals"][display_name] = {
                        "value": audit.get("numericValue"),
                        "rating": _score_to_rating(audit.get("score", 0)),
                        "display": audit.get("displayValue", ""),
                    }

        # Failed SEO audits
        audits = data.get("lighthouseResult", {}).get("audits", {})
        seo_refs = categories.get("seo", {}).get("auditRefs", [])
        for ref in seo_refs:
            audit = audits.get(ref.get("id"), {})
            if audit and audit.get("score") is not None and audit["score"] < 1:
                result["seo_audits"].append({
                    "id": ref["id"],
                    "title": audit.get("title", ""),
                    "description": audit.get("description", ""),
                    "score": int((audit.get("score", 0) or 0) * 100),
                })

        # Performance opportunities
        for audit_id, audit in audits.items():
            savings = audit.get("details", {}).get("overallSavingsMs")
            if savings and savings > 100:
                result["opportunities"].append({
                    "title": audit.get("title", ""),
                    "savings_ms": int(savings),
                    "description": audit.get("description", ""),
                })
        result["opportunities"].sort(key=lambda x: x["savings_ms"], reverse=True)

        return result
    except Exception as e:
        return {"error": str(e)}


def _score_to_rating(score):
    """Convert a Lighthouse score (0-1) to a rating string."""
    if score is None:
        return "unknown"
    if score >= 0.9:
        return "good"
    if score >= 0.5:
        return "needs_improvement"
    return "poor"
