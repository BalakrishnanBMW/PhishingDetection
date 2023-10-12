# Importing required packages
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import re
from tldextract import extract
from datetime import datetime
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import requests
import urllib.parse
import datetime

# Methods
# 1.Having IP address
def url_having_ip(url):
    domain = re.findall(r"//([^/]+)", url)
    if domain:
        domain = domain[0]
        ip_address = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)
        if ip_address:
            return 1
    return -1

# 2.URL length
def url_length(url):
    length = len(url)
    if (length < 54):
        return -1
    elif (54 <= length <= 75):
        return 0
    else:
        return 1

# 3.Shortening service (tiny URL)
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def url_short(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return -1

# 4.Having @ symbol
def having_at_symbol(url):
    symbol = re.findall(r'@', url)
    if (len(symbol) == 0):
        return -1
    else:
        return 1

# 5.Double slash redirection
def doubleSlash(url):
    index_list = []
    start = 0
    while True:
        index = url.find("//", start)
        if index == -1:
            break
        index_list.append(index)
        start = index + 1
    if len(index_list) == 0:
        return 0
    elif len(index_list) > 1 or index_list[-1] != 5 or index_list[-1] != 6:
        return 1
    else:
        return -1

# 6.prefix-suffix
def prefix_suffix(url):
    subDomain, domain, suffix = extract(url)
    if (domain.count('-')):
        return 1
    else:
        return -1

# 7.Having sub-domain
def sub_domain(url):
    ext = extract(url)
    domain = '.'.join(part for part in ext if part)

    if ext.suffix:
        domain = domain.replace('.' + ext.suffix, '')

    num_dots = domain.count('.')

    if num_dots > 2:
        return 1
    elif num_dots == 1:
        return -1
    else:
        return 0

# 8.SSL state(https)
def SSLfinal_State(url):
    try:
        if (re.search('^https', url)):
            usehttps = 1
        else:
            usehttps = 0
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if (certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0]
        trusted_Auth = ['Comodo', 'Symantec', 'GoDaddy', 'GlobalSign', 'DigiCert', 'StartCom', 'Entrust', 'Verizon',
                        'Trustwave', 'Unizeto', 'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions',
                        'SwissSign', 'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster', 'VeriSign']
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear - startingYear

        if ((usehttps == 1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate >= 1)):
            return -1  # legitimate
        elif ((usehttps == 1) and (certificate_Auth not in trusted_Auth)):
            return 0  # suspicious
        else:
            return 1  # phishing

    except Exception as e:
        return 1

# 9.Domain registation length
def domain_registration(url):
    try:
        w = whois.whois(url)
        exp = w.expiration_date
        length = (exp[0] - datetime.now).days
        if (length <= 365):
            return 1
        else:
            return -1
    except:
        return 0

# 10.Https Token
def https_token(url):
    subDomain, domain, suffix = extract(url)
    host = subDomain + '.' + domain + '.' + suffix
    if (host.count('https')):
        return 1
    else:
        return -1

# 11.request URL
def request_url(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain

        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)

        linked_to_same = 0
        avg = 0
        for image in imgs:
            subDomain, domain, suffix = extract(image['src'])
            imageDomain = domain
            if (websiteDomain == imageDomain or imageDomain == ''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)

        for video in vids:
            subDomain, domain, suffix = extract(video['src'])
            vidDomain = domain
            if (websiteDomain == vidDomain or vidDomain == ''):
                linked_to_same = linked_to_same + 1
        linked_outside = total - linked_to_same
        if (total != 0):
            avg = linked_outside / total

        if (avg < 0.22):
            return -1
        elif (0.22 <= avg <= 0.61):
            return 0
        else:
            return 1
    except:
        return 0

# 12.URL of Anchor
def url_of_anchor(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain

        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            subDomain, domain, suffix = extract(anchor['href'])
            anchorDomain = domain
            if (websiteDomain == anchorDomain or anchorDomain == ''):
                linked_to_same = linked_to_same + 1
        linked_outside = total - linked_to_same
        if (total != 0):
            avg = linked_outside / total

        if (avg < 0.31):
            return -1
        elif (0.31 <= avg <= 0.67):
            return 0
        else:
            return 1
    except:
        return 0

# 13.Link in Tags
def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')

        no_of_meta = 0
        no_of_link = 0
        no_of_script = 0
        anchors = 0
        avg = 0
        for meta in soup.find_all('meta'):
            no_of_meta = no_of_meta + 1
        for link in soup.find_all('link'):
            no_of_link = no_of_link + 1
        for script in soup.find_all('script'):
            no_of_script = no_of_script + 1
        for anchor in soup.find_all('a'):
            anchors = anchors + 1
        total = no_of_meta + no_of_link + no_of_script + anchors
        tags = no_of_meta + no_of_link + no_of_script
        if (total != 0):
            avg = tags / total

        if (avg < 0.25):
            return -1
        elif (0.25 <= avg <= 0.81):
            return 0
        else:
            return 1
    except:
        return 0

# 14.submitting information to email
def email_submit(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if (soup.find('mailto:')):
            return 1
        else:
            return -1
    except:
        return 0

# 15.Abnormal URL
def abnormal_url(url):
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.hostname

    try:
        w = whois.whois(hostname)
        registered_domain = w.domain_name[1]

        if registered_domain in url:
            return -1
        else:
            return 1
    except:
        return 1

# 16.Website redirection count
def redirect(url):
    try:
        response = requests.get(url)
        if response == "":
            return 0
        else:
            if len(response.history) <= 2:
                return -1
            else:
                return 1
    except:
        return 0

# 17.Status bar customization
def on_mouseover(url):
    response = requests.get(url)
    if response == "":
        return 0
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return -1

# 18.Disabling right click
def rightClick(url):
    try:
        response = requests.get(url)
        html_content = response.text
        if 'oncontextmenu' in html_content or 'ondragstart' in html_content:
            return 1
    except requests.exceptions.RequestException:
        return 0

    return -1

# 19.I-frame
def iframe(url):
    response = requests.get(url)
    if response == "":
        return 0
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return -1
        else:
            return 1

# 20.Age of Domain
def age_of_domain(url):
    try:
        w = whois.whois(url)
        start_date = w.creation_date
        current_date = datetime.now()
        age = (current_date - start_date[0]).days
        if (age >= 180):
            return -1
        else:
            return 1
    except Exception as e:
        return 0

# 21.DNS record
def dns(url):
    try:
        w = whois.whois(url)
        if w.status:
            return -1
        else:
            return 1
    except Exception as e:
        return 0

# 22.Web traffic
def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = \
            BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                          "xml").find(
                "REACH")['RANK']
        rank = int(rank)
    except:
        return 0
    if rank < 100000:
        return -1
    else:
        return 1

# 23.Google index
def google_index(url):
    google_search_url = f"https://www.google.com/search?q=site:{url}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36'}
    response = requests.get(google_search_url, headers=headers)

    if response.status_code == 200 and "did not match any documents" not in response.text:
        return -1
    else:
        return 1

# 24.No. of links pointing to page
def links_pointing(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    links = soup.find_all('a')
    external_links = 0
    for link in links:
        href = link.get('href')
        if href and 'http' in href and url not in href:
            external_links += 1

    if external_links == 0:
        return 1
    elif external_links > 0 and external_links <= 2:
        return 0
    else:
        return -1

def pred(url):
    # Reading datasets and splits
    data = pd.read_csv("./phishdset.csv")
    X = data.drop(columns=['Result', 'id', 'WebsiteURL'])
    y = data['Result']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Random Forest classifier
    rf = RandomForestClassifier(n_estimators=10, criterion="entropy")
    rf.fit(X_train, y_train)

    lst = [[url_having_ip(url),
            url_length(url),
            url_short(url),
            having_at_symbol(url),
            doubleSlash(url),
            prefix_suffix(url),
            sub_domain(url),
            SSLfinal_State(url),
            domain_registration(url),
            https_token(url),
            request_url(url),
            url_of_anchor(url),
            Links_in_tags(url),
            email_submit(url),
            abnormal_url(url),
            redirect(url),
            on_mouseover(url),
            rightClick(url),
            iframe(url),
            age_of_domain(url),
            dns(url),
            web_traffic(url),
            google_index(url),
            links_pointing(url)
            ]]

    result = rf.predict(lst)

    #appending to dataset
    dct = {
        'having_IP_Address': lst[0][0], 'URL_Length': lst[0][1], 'Shortining_Service': lst[0][2],
        'having_At_Symbol': lst[0][3], 'double_slash_redirecting': lst[0][4], 'Prefix_Suffix': lst[0][5],
        'having_Sub_Domain': lst[0][6], 'SSLfinal_State': lst[0][7], 'Domain_registeration_length': lst[0][8],
        'HTTPS_token': lst[0][9], 'Request_URL': lst[0][10], 'URL_of_Anchor': lst[0][11], 'Links_in_tags': lst[0][12],
        'Submitting_to_email': lst[0][13], 'Abnormal_URL': lst[0][14], 'Redirect': lst[0][15],
        'on_mouseover': lst[0][16],
        'RightClick': lst[0][17], 'Iframe': lst[0][18], 'age_of_domain': lst[0][19], 'DNSRecord': lst[0][20],
        'web_traffic': lst[0][21],
        'Google_Index': lst[0][22], 'Links_pointing_to_page': lst[0][23], 'Result': result[0], 'WebsiteURL': url
    }

    data.loc[len(data)] = pd.Series(dct)
    data.to_csv("./phishdset.csv", index=False)

    # new_row = pd.Series(dct)
    # data = data.append(new_row, ignore_index=True)
    # data.to_csv('phishdset.csv', index=False)

    return result, lst