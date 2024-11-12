-- File: apisix/plugins/token-checker.lua

local core = require("apisix.core")
local jwt = require("resty.jwt")

local plugin_name = "token-checker"

local schema = {
    type = "object",
    properties = {
        custom_issuer_name = {
            type= "string",
            description= "issuer name to match"
        },
        upstream_for_custom_issuer = {  -- Configurable upstream for issuer B
            type = "string",
            description = "Upstream to route traffic to if issuer matches"
        }
    },
    required = {"upstream_for_custom_issuer", "custom_issuer_name"}
}

local _M = {
    version = 0.1,
    priority = 3000,  -- High priority to execute early
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

function _M.access(conf, ctx)
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

    -- here we can heve any sort of logic to check the type of the token
    -- for now since we have considered only about the passenger requests
    -- we have checked the issuer claim in the token payload
    -- Get the issuer ('iss') claim
    local issuer = decoded_token.payload.iss
    if not issuer then
        return 401, { message = "Missing issuer in token" }
    end
    core.log.info("ISSUER_RECEIVED: ", issuer)

    -- Check issuer and act accordingly
    if issuer == conf.custom_issuer_name then
        core.log.info("Issuer matched, redirecting to the custom upstream configured")
        core.request.set_header(ctx, "X-Auth-Proxy", "passenger")
        core.log.info("custom header set in the request")
    end
end

-- Function to be called during the log phase
function _M.log(conf, ctx)
    -- Log the plugin configuration and the request context
    core.log.warn("conf: ", core.json.encode(conf))
    core.log.warn("ctx: ", core.json.encode(ctx, true))
end

return _M
