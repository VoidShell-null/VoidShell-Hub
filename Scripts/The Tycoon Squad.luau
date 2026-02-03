if not VoidShell then
getgenv().VoidShell = true
getgenv().SCRIPT_KEY = ""
loadstring(game:HttpGet("https://api.jnkie.com/api/v1/luascripts/public/bcc55ee31609b83ac5b9694228960c98fe9572d8f7ed2ad2432b27303f2e05c7/download"))()
end