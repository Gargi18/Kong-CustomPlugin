local kong = kong
local cjson = require "cjson"
local http = require "resty.http"
local jwtDec = require "resty.jwt"
local cache = kong.cache
local credential_cache_key = "hard_coded_cachekey"
local upstreamoauth = {
  PRIORITY = 10,
  VERSION = "0.1",
}

local function getBearerToken(plugin_conf)
    local httpc = http.new()
    local req_body, auth_header
    req_body = "grant_type=client_credentials&client_id=" .. plugin_conf.client_id .. "&client_secret=" .. plugin_conf.client_secret
    if plugin_conf.audience ~= nil then
     req_body = req_body .. "&audience=" .. plugin_conf.audience
    end
    if plugin_conf.scope ~= nil then
     req_body = req_body .. "&scope=" .. plugin_conf.scope
    end
  
    local res, err = httpc:request_uri(plugin_conf.token_url, {
      method = "POST",
      body = req_body,
      headers = {
        ["Accept"] = "application/json",
        ["Content-Type"] = "application/x-www-form-urlencoded"
      },
      ssl_verify = plugin_conf.ssl_verify
    })

    if res.status == 200 then
        local body = res.body
        local json_okta_response = cjson.decode(body)
        local response_accesstoken =json_okta_response.access_token
        local expiry_ttl =json_okta_response.expires_in
        return response_accesstoken
      end
      return nil, err
end


local function getCache(credential_cache_key,plugin_conf)
    -- This will add a 28800 second (8 hour) expiring TTL on this cached value
    -- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
    local cacheValue, err = kong.cache:get(credential_cache_key, { ttl = 90 }, getBearerToken,plugin_conf)
      
    if err then

      kong.log.debug("Could not retrieve credentials")
      return
    end
      
    return cacheValue
  end



function upstreamoauth:access(plugin_conf)

       --CACHE LOGIC - Check boolean and then if EOAUTH has existing key -> userInfo value

		local getKongCache = getCache(credential_cache_key,plugin_conf)
		
            kong.service.request.add_header("Authorization", "Bearer " .. getKongCache)
		end
	    
	    -- END OF NEW CACHE LOGIC --


return upstreamoauth
