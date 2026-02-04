import asyncio
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup, SoupStrainer
from .utils import is_valid_domain
from .utils import log_to_server
from .jarm_helper import get_jarm_hash
import mmh3
import codecs

async def get_favicon_hash(session, base_url, config):
    try:
        favicon_url = f"{base_url.rstrip('/')}/favicon.ico"
        async with session.get(favicon_url, timeout=config.timeout, ssl=False) as resp:
            if resp.status == 200:
                favicon = await resp.read()
                return mmh3.hash(codecs.encode(favicon, "base64"))
    except:
        pass
    return None


async def _parseResponse(session, url, port, protocol, ip, common_name, makeRequestByIP, config):
    try:
        if config.semaphore.locked():
            # print("Concurrency limit reached, waiting ...")
            await asyncio.sleep(1)

        redirected_domain = ""
        response_headers = {}
        first_300_words = ""
        title = ""

        async with session.get(
            url, allow_redirects=True, timeout=config.timeout, ssl=False
        ) as res:
            response = await res.text(encoding="utf-8")
            content_type = res.headers.get("Content-Type")

            if res.headers is not None:
                for key, value in res.headers.items():
                    response_headers[key] = value.encode(
                        "utf-8", "surrogatepass"
                    ).decode("utf-8")

            if res.history:
                redirected_domain = str(res.url)

            if response is not None and content_type is not None:
                if "xml" in content_type:
                    root = ET.fromstring(response)
                    xmlwords = []
                    count = 0
                    # iter, loops over the all the subelements  in the XML document
                    for elem in root.iter():
                        if elem.text:
                            xmlwords.extend(elem.text.split())
                            count += len(xmlwords)
                            if count >= 300:
                                break
                    if xmlwords:
                        first_300_words = " ".join(xmlwords[:300])

                elif "html" in content_type:
                    strainer = SoupStrainer(["title", "body"])
                    soup = BeautifulSoup(
                        response,
                        "html.parser",
                        parse_only=strainer,
                    )
                    title_tag = soup.title
                    body_tag = soup.body

                    # .string accesses the string content of the title
                    if title_tag and title_tag.string:
                        title = title_tag.string.strip()

                    if body_tag:
                        # Get all the text within the body tag including text from nested elements
                        body_text = body_tag.get_text(separator=" ", strip=True)
                        # Split the text into words
                        words = body_text.split()
                        # Take the first 300 words
                        first_300_words = " ".join(words[:300])

                    # sometimes there is just text on the website without title/body
                    if not body_tag and not title_tag:
                        words = response.split()
                        # Take the first 300 words
                        first_300_words = " ".join(words[:300])

                # for content-type text/plain
                elif "plain" in content_type:
                    words = response.split()
                    first_300_words = " ".join(words[:300])

                elif "json" in content_type:
                    first_300_words = response[:300]

                # if makeRequestByIP:
                #     print(f"Title: {title} , {protocol}{ip}:{port}")
                # else:
                #     print(f"Title:{title} ,{common_name}")

                # Tech Stack & WAF Detection
                technologies = set()
                waf = None
                
                # Check Headers
                server_header = response_headers.get("Server", "")
                powered_by = response_headers.get("X-Powered-By", "")
                via_header = response_headers.get("Via", "")
                cookie_header = res.headers.get("Set-Cookie", "")
                
                # Tech Signatures
                if "PHP" in powered_by or "PHP" in server_header: technologies.add("PHP")
                if "ASP.NET" in powered_by: technologies.add("ASP.NET")
                if "Express" in powered_by: technologies.add("Express.js")
                if "nginx" in server_header.lower(): technologies.add("Nginx")
                if "apache" in server_header.lower(): technologies.add("Apache")
                if "cloudflare" in server_header.lower(): technologies.add("Cloudflare CDN")
                if "microsoft-iis" in server_header.lower(): technologies.add("IIS")
                
                # WAF Signatures
                if "cloudflare" in server_header.lower() or "__cfduid" in cookie_header:
                    waf = "Cloudflare"
                elif "AWS" in server_header or "CloudFront" in via_header:
                    waf = "AWS CloudFront"
                elif "Akamai" in server_header or "Akamai" in via_header:
                    waf = "Akamai"
                elif "incap_ses" in cookie_header:
                    waf = "Imperva Incapsula"

                # Check Body for Generators
                lower_body = response.lower()
                if "wordpress" in lower_body: technologies.add("WordPress")
                if "react" in lower_body: technologies.add("React")
                if "vue" in lower_body: technologies.add("Vue.js")
                if "bootstrap" in lower_body: technologies.add("Bootstrap")
                
                # Get Favicon Hash
                fav_hash = await get_favicon_hash(session, f"{protocol}{ip if makeRequestByIP else common_name}:{port}", config)
                
                # Get JARM Hash (only on port 443 usually, or ssl ports)
                jarm_hash = None
                if str(port) == "443" or protocol == "https://":
                     # Run in thread as it uses blocking socket
                     jarm_hash = await asyncio.to_thread(get_jarm_hash, ip, int(port))

                # Create a dictionary for the result
                result_dict = {
                    "title": title.encode("utf-8", "surrogatepass").decode(
                        "utf-8"
                    ),
                    "request": f"{protocol}{ip if makeRequestByIP else common_name}:{port}",
                    "redirected_url": redirected_domain,
                    "ip": ip,
                    "port": str(port),
                    "domain": common_name,
                    "response_text": first_300_words,
                    "response_headers": response_headers,
                    "favicon_hash": fav_hash,
                    "jarm_hash": jarm_hash,
                    "technologies": list(technologies),
                    "waf": waf
                }

                return result_dict


    except ET.ParseError as e:
        log_to_server(f"Error parsing XML for {url}: {e}")
    except Exception as e:
        # Send error to dashboard verbose logs
        if makeRequestByIP:
            log_to_server(f"Error for {protocol}{ip}:{port} : {e}")
        else:
            log_to_server(f"Error for {protocol}{common_name}:{port} : {e}")
            
    # Return None if there's an error and the try block doesn't complete
    return None

async def makeGetRequest(session, protocol, ip, common_name, config, makeRequestByIP=True):
    url = ""
    if makeRequestByIP:
        if protocol == "http://":
            httpResults = []
            for port in config.ports:
                url = f"{protocol}{ip}:{port}"
                result = await _parseResponse(session, url, port, protocol, ip, common_name, makeRequestByIP, config)
                if result is not None:
                    httpResults.append(result)
            if httpResults:
                return httpResults
            else:
                return None
        else:
            url = f"{protocol}{ip}:{config.ssl_port}"
            return await _parseResponse(session, url, config.ssl_port, protocol, ip, common_name, makeRequestByIP, config)

    else:
        port = "80" if protocol == "http://" else config.ssl_port
        url = f"{protocol}{common_name}:{port}"
        return await _parseResponse(session, url, port, protocol, ip, common_name, makeRequestByIP, config)

async def check_site(session, ip, common_name, config):
    try:
        temp_dict = {}

        if "*" in common_name or not is_valid_domain(common_name):
            for protocol in config.protocols:
                dict_res = await makeGetRequest(
                    session, protocol, ip, common_name, config, True
                )
                temp_dict[
                    f'{protocol.replace("://", "")}_responseForIP'
                ] = dict_res

        else:
            for protocol in config.protocols:
                dict_res = await makeGetRequest(
                    session, protocol, ip, common_name, config, False
                )
                temp_dict[
                    f'{protocol.replace("://", "")}_responseForDomainName'
                ] = dict_res

            for protocol in config.protocols:
                dict_res = await makeGetRequest(
                    session, protocol, ip, common_name, config, True
                )
                temp_dict[
                    f'{protocol.replace("://", "")}_responseForIP'
                ] = dict_res

        temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
        if temp_dict:
            return temp_dict

    except Exception as e:
        log_to_server(f"Critical Error for {ip}: {e}")

    return None