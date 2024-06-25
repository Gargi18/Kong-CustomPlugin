local kong = kong
local cjson = require "cjson"
local http = require "resty.http"
local cache = kong.cache
local upstreamoauth = {
    PRIORITY = 10,
    VERSION = "0.1"
}

local function getBearerToken(plugin_conf)
    local httpc = http.new()
    local req_body, auth_header
    req_body =
        "grant_type=client_credentials&client_id=" ..
        plugin_conf.client_id .. "&client_secret=" .. plugin_conf.client_secret
		 if plugin_conf.audience ~= nil then
        req_body = req_body .. "&audience=" .. plugin_conf.audience
    end
    if plugin_conf.scope ~= nil then
        req_body = req_body .. "&scope=" .. plugin_conf.scope
    end

    local res, err =
        httpc:request_uri(
        plugin_conf.token_url,
        {
            method = "POST",
            body = req_body,
            headers = {
                ["Accept"] = "application/json",
                ["Content-Type"] = "application/x-www-form-urlencoded"
            },
            ssl_verify = plugin_conf.ssl_verify
        }
    )

    if res.status == 200 then
        local body = res.body
		local json_okta_response = cjson.decode(body)
        local encodedToken = cjson.encode({
    access_token = json_okta_response.access_token,
    expiry_in = tonumber(json_okta_response.expires_in) + os.time()
	})
    return encodedToken
    end
    return nil, err
end

function upstreamoauth:access(plugin_conf)
    --CACHE LOGIC - Check boolean and then if EOAUTH has existing key -> userInfo value
    local curtime = os.time()
   local cache_key = "upstream_oauth2_token_" .. plugin_conf.client_id

   local cacheValue, err = kong.cache:get(cache_key,nil,getBearerToken, plugin_conf)
   if err then
       kong.log.err(err)
	   return kong.response.exit(500, {
       message = "Unexpected error"
    })
    end
	
	
	 local expiry_time = cjson.decode(cacheValue).expiry_in

	if (expiry_time <= curtime + 60 ) then
	kong.cache:invalidate_local(cache_key)
	cacheValue, err = kong.cache:get(cache_key,nil,getBearerToken, plugin_conf)
	end
	
	 local access_token = cjson.decode(cacheValue).access_token
    
	kong.service.request.add_header("Authorization", "Bearer " .. access_token)

end

-- END OF NEW CACHE LOGIC --

return upstreamoauth
