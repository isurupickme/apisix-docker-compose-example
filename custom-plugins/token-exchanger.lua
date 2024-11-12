-- File: apisix/plugins/token-exchanger.lua

local core = require("apisix.core")
local http = require("resty.http")  -- To perform HTTP requests to the 3rd party API
local jwt = require("resty.jwt")

local plugin_name = "token-exchanger"

local schema = {
    type = "object",
    properties = {
        custom_issuer_name = {
            type= "string",
            description= "Issuer name to match"
        },
        token_exchange_service_uri = {  -- URL for the 3rd party API to get a new token
            type = "string",
            description = "URL of the 3rd party token provider"
        }
    },
    required = {"custom_issuer_name", "token_exchange_service_uri"}
}

local _M = {
    version = 0.1,
    priority = 4001,  -- High priority to execute early
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    return true
end

function _M.rewrite(conf, ctx)
    -- Extract JWT token from Authorization header
    local token = core.request.header(ctx, "Authorization")
    if not token then
        return 401, { message = "Missing token" }
    end

    local jwt_token = string.match(token, "Bearer%s+(.+)")
    if not jwt_token then
        return 401, { message = "Invalid token format" }
    end

    -- Decode JWT token
    local decoded_token, err = jwt:load_jwt(jwt_token)
    if err then
        return 401, { message = "Invalid token" }
    end

    -- Get the issuer ('iss') claim
    local issuer = decoded_token.payload.iss
    if not issuer then
        return 401, { message = "Missing issuer in token" }
    end
    core.log.info("ISSUER_RECEIVED: ", issuer)

    -- If the issuer is the custom one (e.g., "passenger"), fetch new token from the 3rd party API
    if issuer == conf.custom_issuer_name then
        core.log.info("Issuer matched, calling 3rd party API to fetch new token")

        -- Create an HTTP client to call the 3rd party API
        local httpc = http.new()
        local res, err2 = httpc:request_uri(conf.token_exchange_service_uri, {
            method = "GET",  -- Change method if necessary
            headers = {
                ["Authorization"] = token,  -- Optionally send the original token
                ["Content-Type"] = "application/json"
            },
        })

        if not res then
            core.log.error("Failed to call 3rd party API: ", err2)
            return 500, { message = "Failed to fetch new token" }
        end

        -- Check the response status code
        -- If status is 403 or 401, it means the token is expired or invalid, so return 401
        if res.status == 403 or res.status == 401 then
            return 401, { message = "Unauthorized: Token expired or invalid" }
        end

        -- if statis is not 200, it means there was an error, so return 500
        if res.status ~= 200 then
            core.log.error("Failed to fetch new token: ", res.status, res.body)
            return 500, { message = "Something went wrong while fetching new token" }
        end

        -- Parse the response to get the new token
        local response_body = core.json.decode(res.body)
        if not response_body or not response_body.new_token then
            core.log.error("Invalid response from 3rd party API: ", res.body)
            return 500, { message = "Invalid response from token service" }
        end

        local new_token = response_body.new_token
        core.log.info("Received new token from 3rd party API: ", new_token)

        -- Replace the current token in the Authorization header
        core.request.set_header(ctx, "Authorization", "Bearer " .. new_token)
        core.log.info("Authorization header updated with new token")
    end
end

function _M.log(conf, ctx)
    -- Log the plugin configuration and the request context
    core.log.warn("conf: ", core.json.encode(conf))
    core.log.warn("ctx: ", core.json.encode(ctx, true))
end

return _M
