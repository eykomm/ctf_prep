import base64

while True:
	string = raw_input('Base64 String: ' ).strip()
	print base64.decodestring(string)

