from burp import IBurpExtender
from burp import IHttpListener
import re
import uuid


class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("UUID Randomizer")
        print("UUID Randomizer Installed")
        callbacks.issueAlert("UUID randomization is turned on")
        
    def getRequestHeaderAndBody(self, content):
        request = content.getRequest()
        request_data = self._helpers.analyzeRequest(request)
        headers = list(request_data.getHeaders())
        body = request[request_data.getBodyOffset():].tostring()
        return headers, body
            
    def processHttpMessage(self, tool, is_request, content):
        headers, body = self.getRequestHeaderAndBody(content)

        #Modifying current request to replace new requests        
        work = {}
        pattern = re.compile('[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}')
        
        matches = re.findall(pattern, body)
        print(matches)
        
        for match in matches:
            work[match] = str(uuid.uuid4())
            body = body.replace(match, work[match])

        print(work)

        #Build new request
        new_message = self._helpers.buildHttpMessage(headers, body)
        content.setRequest(new_message)
