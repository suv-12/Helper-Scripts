import requests
import re
import uuid

work ={}

res = requests.get("https://www.uuidgenerator.net/api/version4/10")

pattern = re.compile('[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}')

matches = re.findall(pattern,res.text)

#print (res.text)

for match in matches:
	work[match] = str(uuid.uuid4())

print (work)