-- Brief description

description=[[

      if want to know the installed technologies inside the network or in the cloud you can use this script.
      if you want to search for keywords within the HTTP http response body you can use this script.

]]

-- Author
 
author = "malduhaymi"

-- Usage

---

-- nmap -p <port>  --script findkeywords.nse <host> --script-args "keywords='yourKeyWords'" 

--

-- @output

-- PORT           STATE SERVICE

-- 80/tcp open  ppp

-- | Keyword Found


-- Imports

local http = require "http"

local nmap = require "nmap"

local stdnse = require "stdnse"


-- RULE SECTION

portrule = function(host, port)

  local auth_port = { number=80, protocol="tcp" }

  local identd = nmap.get_port_state(host, auth_port)

  return identd ~= nil

    and identd.state == "open"

    and port.protocol == "tcp"

   and port.state == "open"

end



-- ACTION SECTION

local URL = "/"

local function searchForKeyword(host, port)
	
      local resp = http.get(host, port, URL)
     local keyword = stdnse.get_script_args("aldeheme.keywords")
     if(keyword == nil or keyword == "" or keyword == "\n" or keyword == "\n") then
	return "empty keyword"
     end
      if not http.response_contains(resp, keyword) then
            return false

      end
      return resp

end

action = function(host, port)

      local outPut = searchForKeyword(host, port)
      
      if not outPut then
            return "Keyword Not Found"
      end
 
  return "Keyword Found"

end