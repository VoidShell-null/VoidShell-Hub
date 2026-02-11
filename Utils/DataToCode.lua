--[[
	DataToCode - Make DataTypes actually readable (Executor-Compatible Version)
	
	- Modified by nullspecter. 
	- MIT
	
	Original by: https://github.com/78n
	License: https://github.com/78n/Roblox/blob/main/LICENSE | Covered by MIT
	
	-- Conversion Notes for Executors --
	- This version is specifically adapted for client-side script execution environments.
	- Removed dependency on 'SharedTable', which does not exist in executors.
	- Added a fallback for the 'vector' library, as it may not be present.
	- Simplified logic to be client-only (removed server-side paths).
	- Relies on the native 'getrenv' provided by the executor.
]]

local assert, type, typeof, rawset, getmetatable, tostring = assert, type, typeof, rawset, getmetatable, tostring
local print, warn, pack, unpack, next = print, warn, table.pack, unpack, next

-- Executor environment check for the vector library
local hasVectorLib = type(vector) == "table" and type(vector.create) == "function"

local bufftostring, fromstring, readu8 = buffer.tostring, buffer.fromstring, buffer.readu8
local isfrozen, concat = table.isfrozen, table.concat
local info = debug.info

local DefaultMethods = {}
local Methods = setmetatable({}, {__index = DefaultMethods})
local Class = {
	Methods = Methods,
	_tostringUnsupported = false,
	_Serializeinf = false,
	__VERSION = "1.1-Executor"
}

local Keywords = {
	["local"] = "\"local\"",
	["function"] = "\"function\"",
	["and"] = "\"and\"",
	["break"] = "\"break\"",
	["not"] = "\"not\"",
	["or"] = "\"or\"",
	["else"] = "\"else\"",
	["elseif"] = "\"elseif\"",
	["if"] = "\"if\"",
	["then"] = "\"then\"",
	["until"] = "\"until\"",
	["repeat"] = "\"repeat\"",
	["while"] = "\"while\"",
	["do"] = "\"do\"",
	["for"] = "\"for\"",
	["in"] = "\"in\"",
	["end"] = "\"end\"",
	["return"] = "\"return\"",
	["true"] = "\"true\"",
	["false"] = "\"false\"",
	["nil"] = "\"nil\""
}

local weakkeys = {__mode = "k"}

local islclosure = islclosure or function(Function)
	return info(Function, "l") ~= -1
end

local DefaultVectors, DefaultCFrames = {}, {} do
	local function ExtractTypes(DataTypeLibrary, Path, DataType, Storage)
        if not DataTypeLibrary then return end -- Guard against missing libs
		for i,v in next, DataTypeLibrary do
			if typeof(v) == DataType and not Storage[v] and type(i) == "string" and not Keywords[i] or not i:match("[a-Z_][a-Z_0-9]") then
				Storage[v] = Path.."."..i
			end
		end
	end

    if hasVectorLib then
	    ExtractTypes(vector, "vector", "Vector3", DefaultVectors)
    end
	ExtractTypes(Vector3, "Vector3", "Vector3", DefaultVectors)
	ExtractTypes(CFrame, "CFrame", "CFrame", DefaultCFrames)

	Class.DefaultTypes = {
		Vector3 = DefaultVectors,
		CFrame = DefaultCFrames,
	}
end

local function Serialize(DataStructure, format, indents, CyclicList, InComment)
	local DataHandler = Methods[typeof(DataStructure)]
	return if DataHandler then DataHandler(DataStructure, format, indents, CyclicList, InComment) else "nil --["..(if InComment then "" else "=").."[ Unsupported Data Type | "..typeof(DataStructure)..(if not Class._tostringUnsupported then "" else " | "..tostring(DataStructure)).." ]"..(if not InComment then "" else "=").."]"
end

local function ValidateIndex(Index)
	local IndexType = type(Index)
	local IsNumber = IndexType == "number"
	if IsNumber or IndexType == "string" then
		local IsKeyword = if IsNumber then Index else Keywords[Index]
		if not IsKeyword then
			if Index ~= "" then
				local IndexBuffer = fromstring(Index)
				local FirstByte = readu8(IndexBuffer, 0)
				if FirstByte >= 97 and FirstByte <= 122 or FirstByte >= 65 and FirstByte <= 90 or FirstByte == 95 then
					for i = 1, #Index-1 do
						local Byte = readu8(IndexBuffer, i)
						if not ((Byte >= 97 and Byte <= 122) or (Byte >= 65 and Byte <= 90) or Byte == 95 or (Byte >= 48 and Byte <= 57)) then
							return "["..Methods.string(Index).."] = "
						end
					end
					return Index.." = "
				end
				return "["..Methods.string(Index).."] = "
			end
			return "[\"\"] = "
		end
		return "["..IsKeyword.."] = "
	end
	return "["..(if IndexType ~= "table" then Serialize(Index, false, "") else "\"<Table> (table: "..(if getmetatable(Index) == nil then tostring(Index):sub(8) else "@metatable")..")\"").."] = "
end

-- All DefaultMethods (unchanged from original except for Instance, SharedTable, and Vector3)
function DefaultMethods.Axes(Axes) return "Axes.new("..concat({if Axes.X then "Enum.Axis.X" else nil,if Axes.Y then "Enum.Axis.Y" else nil,if Axes.Z then "Enum.Axis.Z" else nil},", ")..")" end
function DefaultMethods.BrickColor(Color) return "BrickColor.new("..Methods.string(Color.Name)..")" end
function DefaultMethods.CFrame(CFrame)
	local Generation = DefaultCFrames[CFrame]
	if not Generation then
		local x, y, z, R00, R01, R02, R10, R11, R12, R20, R21, R22 = CFrame:GetComponents()
		local SerializeNumber = Methods.number
		return "CFrame.new("..SerializeNumber(x)..", "..SerializeNumber(y)..", "..SerializeNumber(z)..", "..SerializeNumber(R00)..", "..SerializeNumber(R01)..", "..SerializeNumber(R02)..", "..SerializeNumber(R10)..", "..SerializeNumber(R11)..", "..SerializeNumber(R12)..", "..SerializeNumber(R20)..", "..SerializeNumber(R21)..", "..SerializeNumber(R22)..")"
	end
	return Generation
end
do
	local DefaultCatalogSearchParams = CatalogSearchParams.new()
	function DefaultMethods.CatalogSearchParams(Params, format, indents)
		if DefaultCatalogSearchParams ~= Params then
			local formatspace = if format then "\n"..indents else " " local SerializeString = Methods.string
			return "(function(Param) "..formatspace..(if Params.SearchKeyword ~= "" then "\tParam.SearchKeyword = "..SerializeString(Params.SearchKeyword)..formatspace else "")..(if Params.MinPrice ~= 0 then "\tParam.MinPrice = "..Params.MinPrice..formatspace else "")..(if Params.MaxPrice ~= 2147483647 then "\tParam.MaxPrice = "..Params.MaxPrice..formatspace else "")..(if Params.SortType ~= Enum.CatalogSortType.Relevance then "\tParam.SortType = Enum.CatalogSortType."..Params.SortType.Name..formatspace else "")..(if Params.SortAggregation ~= Enum.CatalogSortAggregation.AllTime then "\tParam.SortAggregation = Enum.CatalogSortAggregation."..Params.SortAggregation.Name..formatspace else "")..(if Params.CategoryFilter ~= Enum.CatalogCategoryFilter.None then "\tParam.CategoryFilter = Enum.CatalogCategoryFilter."..Params.CategoryFilter.Name..formatspace else "")..(if Params.SalesTypeFilter ~= Enum.SalesTypeFilter.All then "\tParam.SalesTypeFilter = Enum.SalesTypeFilter."..Params.SalesTypeFilter.Name..formatspace else "")..(if #Params.BundleTypes > 0 then "\tParam.BundleTypes = "..Methods.table(Params.BundleTypes, false, "")..formatspace else "")..(if #Params.AssetTypes > 0 then "\tParam.AssetTypes = "..Methods.table(Params.AssetTypes, false, "")..formatspace else "")..(if Params.IncludeOffSale then "\tParam.IncludeOffSale = true"..formatspace else "")..(if Params.CreatorName ~= "" then "\tParam.CreatorName = "..SerializeString(Params.CreatorName)..formatspace else "")..(if Params.CreatorType ~= Enum.CreatorTypeFilter.All then "\tParam.CreatorType = Enum.CreatorTypeFilter."..Params.CreatorType.Name..formatspace else "")..(if Params.CreatorId ~= 0 then "\tParam.CreatorId = "..Params.CreatorId..formatspace else "")..(if Params.Limit ~= 30 then "\tParam.Limit = "..Params.Limit..formatspace else "").."\treturn Param"..formatspace.."end)(CatalogSearchParams.new())"
		end
		return "CatalogSearchParams.new()"
	end
end
function DefaultMethods.Color3(Color) local SerializeNumber = Methods.number return "Color3.new("..SerializeNumber(Color.R)..", "..SerializeNumber(Color.G)..", "..SerializeNumber(Color.B)..")" end
function DefaultMethods.ColorSequence(Sequence) local SerializeColorSequenceKeypoint = Methods.ColorSequenceKeypoint local Keypoints = Sequence.Keypoints local Size = #Keypoints local Serialized = "" for i = 1, Size-1 do Serialized ..= SerializeColorSequenceKeypoint(Keypoints[i])..", " end return "ColorSequence.new({"..Serialized..SerializeColorSequenceKeypoint(Keypoints[Size]).."})" end
function DefaultMethods.ColorSequenceKeypoint(KeyPoint) return "ColorSequenceKeypoint.new("..Methods.number(KeyPoint.Time)..", "..Methods.Color3(KeyPoint.Value)..")" end
function DefaultMethods.Content(content) return if content.Uri then 'Content.fromUri("'..content.Uri..'")' else "Content.none" end
function DefaultMethods.DateTime(Date) return "DateTime.fromUnixTimestampMillis("..Date.UnixTimestampMillis..")" end
function DefaultMethods.DockWidgetPluginGuiInfo(Dock) local ArgumentFunction = tostring(Dock):gmatch(":([%w%-]+)") return "DockWidgetPluginGuiInfo.new(Enum.InitialDockState."..ArgumentFunction()..", "..(if ArgumentFunction() == "1" then "true" else "false")..", "..(if ArgumentFunction() == "1" then "true" else "false")..", "..ArgumentFunction()..", "..ArgumentFunction()..", "..ArgumentFunction()..", "..ArgumentFunction()..")" end
function DefaultMethods.Enum(Enum) return "Enums."..tostring(Enum) end
do local Enums = {} for i,v in Enum:GetEnums() do Enums[v] = "Enum."..tostring(v) end function DefaultMethods.EnumItem(Item) return Enums[Item.EnumType].."."..Item.Name end end
function DefaultMethods.Enums() return "Enums" end
function DefaultMethods.Faces(Faces) return "Faces.new("..concat({if Faces.Top then "Enum.NormalId.Top" else nil,if Faces.Bottom then "Enum.NormalId.Bottom" else nil,if Faces.Left then "Enum.NormalId.Left" else nil,if Faces.Right then "Enum.NormalId.Right" else nil,if Faces.Back then "Enum.NormalId.Back" else nil,if Faces.Front then "Enum.NormalId.Front" else nil}, ", ")..")" end
function DefaultMethods.FloatCurveKey(CurveKey) local SerializeNumber = Methods.number return "FloatCurveKey.new("..SerializeNumber(CurveKey.Time)..", "..SerializeNumber(CurveKey.Value)..", Enum.KeyInterpolationMode."..CurveKey.Interpolation.Name..")" end
function DefaultMethods.Font(Font) return "Font.new("..Methods.string(Font.Family)..", Enum.FontWeight."..Font.Weight.Name..", Enum.FontStyle."..Font.Style.Name..")" end

-- EXECUTOR CHANGE: Simplified Instance logic to be client-only
do
	local Players = game:GetService("Players")
	local FindService = game.FindService
	local Services = {Workspace = "workspace", Lighting = "game.Lighting", GlobalSettings = "settings()", Stats = "stats()", UserSettings = "UserSettings()", PluginManagerInterface = "PluginManager()", DebuggerManager = "DebuggerManager()"}
	local LocalPlayer = Players.LocalPlayer or Players:GetPropertyChangedSignal("LocalPlayer"):Wait()

	function DefaultMethods.Instance(obj) -- Executor is always client
		local ObjectParent = obj.Parent
		local ObjectClassName = obj.ClassName
		if ObjectParent then
			local ObjectName = Methods.string(obj.Name)
			if ObjectClassName ~= "Model" and ObjectClassName ~= "Player" then
				local IsService, Output = pcall(FindService, game, ObjectClassName)
				return if not (IsService and Output) then Methods.Instance(ObjectParent)..":WaitForChild("..ObjectName..")" else Services[ObjectClassName] or "game:GetService(\""..ObjectClassName.."\")"
			elseif ObjectClassName == "Model" then
				local Player = Players:GetPlayerFromCharacter(obj)
				return if not Player then Methods.Instance(ObjectParent)..":WaitForChild("..ObjectName..")" else "game:GetService(\"Players\")".. (if Player == LocalPlayer then ".LocalPlayer.Character" else ":WaitForChild("..ObjectName..").Character")
			end
			return "game:GetService(\"Players\")".. (if obj == LocalPlayer then ".LocalPlayer" else ":WaitForChild("..ObjectName..")")
		end
		return if ObjectClassName == "DataModel" then "game" else "Instance.new(\""..ObjectClassName.."\", nil)"
	end
	Class.Services = Services
end

function DefaultMethods.NumberRange(Range) local SerializeNumber = Methods.number return "NumberRange.new("..SerializeNumber(Range.Min)..", "..SerializeNumber(Range.Max)..")" end
function DefaultMethods.NumberSequence(Sequence) local SerializeNumberSequenceKeypoint = Methods.NumberSequenceKeypoint local Keypoints = Sequence.Keypoints local Size = #Keypoints local Serialized = "" for i = 1, Size-1 do Serialized ..= SerializeNumberSequenceKeypoint(Keypoints[i])..", " end return "NumberSequence.new({"..Serialized..SerializeNumberSequenceKeypoint(Keypoints[Size]).."})" end
do local DefaultOverlapParams = OverlapParams.new() function DefaultMethods.OverlapParams(Params, format, indents) if DefaultOverlapParams ~= Params then local formatspace = format and "\n"..indents or " " return "(function(Param) "..formatspace..(if #Params.FilterDescendantsInstances > 0 then "\tParam.FilterDescendantsInstances = "..Methods.table(Params.FilterDescendantsInstances, false, "")..formatspace else "")..(if Params.FilterType ~= Enum.RaycastFilterType.Exclude then "\tParam.FilterType = Enum.RaycastFilterType."..Params.FilterType.Name..formatspace else "")..(if Params.CollisionGroup ~= "Default" then "\tParam.CollisionGroup = "..Methods.string(Params.CollisionGroup)..formatspace else "")..(if Params.RespectCanCollide then "\tParam.RespectCanCollide = true"..formatspace else "")..(if Params.BruteForceAllSlow then "\tParam.BruteForceAllSlow = true"..formatspace else "").."\treturn Param"..formatspace.."end)(OverlapParams.new())" end return "OverlapParams.new()" end end
function DefaultMethods.NumberSequenceKeypoint(Keypoint) local SerializeNumber = Methods.number return "NumberSequenceKeypoint.new("..SerializeNumber(Keypoint.Time)..", "..SerializeNumber(Keypoint.Value)..", "..SerializeNumber(Keypoint.Envelope)..")" end
function DefaultMethods.PathWaypoint(Waypoint) return "PathWaypoint.new("..Methods.Vector3(Waypoint.Position)..", Enum.PathWaypointAction."..Waypoint.Action.Name..", "..Methods.string(Waypoint.Label)..")" end
do local function nanToString(num) return if num == num then num else "0/0" end function DefaultMethods.PhysicalProperties(Properties) return "PhysicalProperties.new("..(nanToString(Properties.Density))..", "..nanToString(Properties.Friction)..", "..nanToString(Properties.Elasticity)..", "..nanToString(Properties.FrictionWeight)..", "..nanToString(Properties.ElasticityWeight)..")" end end
function DefaultMethods.RBXScriptConnection(Connection, _, _, _, InComment) local CommentSeperator = if not InComment then "" else "=" return "(nil --["..CommentSeperator.."[ RBXScriptConnection | IsConnected: "..(if Connection.Connected then "true" else "false").." ]"..CommentSeperator.."])" end
do local Signals = {GraphicsQualityChangeRequest = "game.GraphicsQualityChangeRequest",AllowedGearTypeChanged = "game.AllowedGearTypeChanged",ScreenshotSavedToAlbum = "game.ScreenshotSavedToAlbum",UniverseMetadataLoaded = "game.UniverseMetadataLoaded",ScreenshotReady = "game.ScreenshotReady",ServiceRemoving = "game.ServiceRemoving",ServiceAdded = "game.ServiceAdded",ItemChanged = "game.ItemChanged",CloseLate = "game.CloseLate",Loaded = "game.Loaded",Close = "game.Close",RobloxGuiFocusedChanged = "game:GetService(\"RunService\").RobloxGuiFocusedChanged",PostSimulation = "game:GetService(\"RunService\").PostSimulation",RenderStepped = "game:GetService(\"RunService\").RenderStepped",PreSimulation = "game:GetService(\"RunService\").PreSimulation",PreAnimation = "game:GetService(\"RunService\").PreAnimation",PreRender = "game:GetService(\"RunService\").PreRender",Heartbeat = "game:GetService(\"RunService\").Heartbeat",Stepped = "game:GetService(\"RunService\").Stepped"} function DefaultMethods.RBXScriptSignal(Signal, _, _, _, InComment) local CommentSeperator = if not InComment then "" else "=" local SignalName = tostring(Signal):match("Signal ([A-z]+)") return Signals[SignalName] or "(nil --["..CommentSeperator.."[ RBXScriptSignal | "..SignalName.." is not supported ]"..CommentSeperator.."])" end Class.Signals = Signals end
function DefaultMethods.Random(_, _, _, _, InComment) local CommentSeperator = if not InComment then "" else "=" return "Random.new(--["..CommentSeperator.."[ <Seed> ]"..CommentSeperator.."])" end
function DefaultMethods.Ray(Ray) local SerializeVector3 = Methods.Vector3 return "Ray.new("..SerializeVector3(Ray.Origin)..", "..SerializeVector3(Ray.Direction)..")" end
do local DefaultRaycastParams = RaycastParams.new() function DefaultMethods.RaycastParams(Params, format, indents) if DefaultRaycastParams ~= Params then local formatspace = format and "\n"..indents or " " return "(function(Param) "..formatspace..(if #Params.FilterDescendantsInstances > 0 then "\tParam.FilterDescendantsInstances = "..Methods.table(Params.FilterDescendantsInstances, false, "")..formatspace else "")..(if Params.FilterType ~= Enum.RaycastFilterType.Exclude then "\tParam.FilterType = Enum.RaycastFilterType."..Params.FilterType.Name..formatspace else "")..(if Params.IgnoreWater then "\tParam.IgnoreWater = true"..formatspace else "")..(if Params.CollisionGroup ~= "Default" then "\tParam.CollisionGroup = "..Methods.string(Params.CollisionGroup)..formatspace else "")..(if Params.RespectCanCollide then "\tParam.RespectCanCollide = true"..formatspace else "")..(if Params.BruteForceAllSlow then "\tParam.BruteForceAllSlow = true"..formatspace else "").."\treturn Param"..formatspace.."end)(RaycastParams.new())" end return "RaycastParams.new()" end end
function DefaultMethods.Rect(Rect) local SerializeVector2 = Methods.Vector2 return "Rect.new("..SerializeVector2(Rect.Min)..", "..SerializeVector2(Rect.Max)..")" end
function DefaultMethods.Region3(Region) local SerializeVector3 = Methods.Vector3 local Center = Region.CFrame.Position local Size = Region.Size/2 return "Region3.new("..SerializeVector3(Center - Size)..", "..SerializeVector3(Center + Size)..")" end
function DefaultMethods.Region3int16(Region) local SerializeVector3int16 = Methods.Vector3int16 return "Region3int16.new("..SerializeVector3int16(Region.Min)..", "..SerializeVector3int16(Region.Max)..")" end
function DefaultMethods.RotationCurveKey(Curve) return "RotationCurveKey.new("..Methods.number(Curve.Time)..", "..Methods.CFrame(Curve.Value)..", Enum.KeyInterpolationMode."..Curve.Interpolation.Name..")" end

-- EXECUTOR CHANGE: SharedTable does not exist.
function DefaultMethods.SharedTable(Shared, format, indents, _, InComment)
	return "(nil --[[ Unsupported: SharedTable is not available in executor environments ]])"
end

function DefaultMethods.TweenInfo(Info) return "TweenInfo.new("..Methods.number(Info.Time)..", Enum.EasingStyle."..Info.EasingStyle.Name..", Enum.EasingDirection."..Info.EasingDirection.Name..", "..Info.RepeatCount..", "..(if Info.Reverses then "true" else "false")..", "..Methods.number(Info.DelayTime)..")" end
function DefaultMethods.UDim(UDim) return "UDim.new("..Methods.number(UDim.Scale)..", "..UDim.Offset..")" end
function DefaultMethods.UDim2(UDim2) local SerializeNumber = Methods.number return "UDim2.new("..SerializeNumber(UDim2.X.Scale)..", "..UDim2.X.Offset..", "..SerializeNumber(UDim2.Y.Scale)..", "..UDim2.Y.Offset..")" end
function DefaultMethods.Vector2(Vector) local SerializeNumber = Methods.number return "Vector2.new("..SerializeNumber(Vector.X)..", "..SerializeNumber(Vector.Y)..")" end
function DefaultMethods.Vector2int16(Vector) return "Vector2int16.new("..Vector.X..", "..Vector.Y..")" end

-- EXECUTOR CHANGE: Handle potentially missing `vector` library.
function DefaultMethods.Vector3(Vector)
	local gen = DefaultVectors[Vector]
	if gen then return gen end

	local SerializeNumber = Methods.number
	local x, y, z = SerializeNumber(Vector.X), SerializeNumber(Vector.Y), SerializeNumber(Vector.Z)

	if hasVectorLib then
		return "vector.create("..x..", "..y..", "..z..")" -- Prefer vector lib if available
	else
		return "Vector3.new("..x..", "..y..", "..z..")" -- Fallback
	end
end

function DefaultMethods.Vector3int16(Vector) return "Vector3int16.new("..Vector.X..", "..Vector.Y..", "..Vector.Z..")" end
function DefaultMethods.boolean(bool) return if bool then "true" else "false" end
function DefaultMethods.buffer(buff) return "buffer.fromstring("..Methods.string(bufftostring(buff))..")" end

-- EXECUTOR CHANGE: Rely on native `getrenv` instead of a polyfill.
do
	local GlobalFunctions = {}
	if getrenv then
		local Visited = setmetatable({}, weakkeys)
		for i, v in getrenv() do
			local ElementType = type(i) == "string" and type(v)
			if ElementType then
				if ElementType == "table" then
					local function LoadLibrary(Path, tbl)
						if not Visited[tbl] then
							Visited[tbl] = true
							for i, v in next, tbl do
								local Type = type(i) == "string" and not Keywords[i] and i:match("[A-z_][A-z_0-9]") and type(v)
								local NewPath = Type and (Type == "function" or Type == "table") and Path.."."..i
								if NewPath then
									if Type == "function" then GlobalFunctions[v] = NewPath else LoadLibrary(NewPath, v) end
								end
							end
							Visited[tbl] = nil
						end
					end
					LoadLibrary(i, v)
					table.clear(Visited)
				elseif ElementType == "function" then
					GlobalFunctions[v] = i
				end
			end
		end
	end
	Class.GlobalFunctions = GlobalFunctions

	DefaultMethods["function"] = function(Function, format, indents, _, InComment)
		local IsGlobal = GlobalFunctions[Function]
		if not IsGlobal then
			if format then
				local SerializeString = Methods.string
				local CommentSeperator = if not InComment then "" else "=" local tempindents = indents.."\t\t\t" local newlineindent = ",\n"..tempindents
				local source, line, name, numparams, vargs = info(Function, "slna")
				local lclosure = line ~= -1
				return (if lclosure then "" else "coroutine.wrap(").."function()\n\t"..indents.."--["..CommentSeperator.."[\n\t\t"..indents.."info = {\n"..tempindents.."source = "..SerializeString(source)..newlineindent.."line = "..line..newlineindent.."what = "..(if lclosure then "\"Lua\"" else "\"C\"")..newlineindent.."name = "..SerializeString(name)..newlineindent.."numparams = "..numparams..newlineindent.."vargs = "..(if vargs then "true" else "false")..newlineindent.."function = "..tostring(Function).."\n\t\t"..indents.."}\n\t"..indents.."]"..CommentSeperator.."]\n"..indents.."end"..(if lclosure then "" else ")")
			end
			return if islclosure(Function) then "function() end" else "coroutine.wrap(function() end)"
		end
		return IsGlobal
	end
end

function DefaultMethods.table(tbl, format, indents, CyclicList, InComment)
	if not CyclicList then CyclicList = setmetatable({}, weakkeys) end
	if not CyclicList[tbl] then
		local isreadonly = isfrozen(tbl)
		local Index, Value = next(tbl)
		if Index ~= nil then
			local Indents = indents..(if format then "\t" else "")
			local Ending = (if format then ",\n" else ", ")
			local formatspace = if format then "\n" else ""
			local Generation = "{"..formatspace
			local CurrentIndex = 1
			CyclicList[tbl] = true
			repeat
				Generation ..= Indents..(if CurrentIndex ~= Index then ValidateIndex(Index) else "")..Serialize(Value, format, Indents, CyclicList, InComment)
				Index, Value = next(tbl, Index)
				Generation ..= if Index ~= nil then Ending else formatspace..indents.."}"
				CurrentIndex += 1
			until Index == nil
			CyclicList[tbl] = nil
			return if not isreadonly then Generation else "table.freeze("..Generation..")"
		end
		return if not isreadonly then "{}" else "table.freeze({})"
	else
		return "*** cycle table reference detected ***"
	end
end
DefaultMethods["nil"] = function() return "nil" end
function DefaultMethods.number(num)
    if num ~= num then
        return "0/0"
    elseif num == 1/0 then
        return "1/0"
    elseif num == -1/0 then
        return "-1/0"
    end;
    if num % 1 == 0 then
        return tostring(num)
    end;
    local abs = math.abs
    for precision = 1, 15 do
        local formatted = string.format("%." .. precision .. "f", num)
        local parsed    = tonumber(formatted)
        if parsed and abs(parsed - num) < 1e-7 * math.max(1, abs(num)) then
            formatted = formatted:gsub("(%..-)0+$", "%1"):gsub("%.$", "")
            return formatted
        end
    end;
    return tostring(num)
end
do local ByteList = {["\a"] = "\\a",["\b"] = "\\b",["\t"] = "\\t",["\n"] = "\\n",["\v"] = "\\v",["\f"] = "\\f",["\r"] = "\\r",["\""] = "\\\"",["\\"] = "\\\\"} for i = 0, 255 do local Character = (i < 32 or i > 126) and string.char(i) if Character and not ByteList[Character] then ByteList[Character] = ("\\%03d"):format(i) end end function DefaultMethods.string(RawString) return "\""..RawString:gsub("[\0-\31\34\92\127-\255]", ByteList).."\"" end end
function DefaultMethods.thread(thread) return "coroutine.create(function() end)" end
function DefaultMethods.userdata(userdata) return getmetatable(userdata) ~= nil and "newproxy(true)" or "newproxy(false)" end
do local SecurityCapabilityEnums = Enum.SecurityCapability:GetEnumItems() function DefaultMethods.SecurityCapabilities(Capabilities) local ContainedCapabilities = {} local CurrentIndex = 1 for i,v in SecurityCapabilityEnums do if Capabilities:Contains(v) then ContainedCapabilities[CurrentIndex] = "Enum.SecurityCapability."..v.Name CurrentIndex += 1 end end return "SecurityCapabilities.new("..concat(ContainedCapabilities, ", ")..")" end end
function DefaultMethods.PluginDrag(Drag) local SerializeString = Methods.string return "PluginDrag.new("..SerializeString(Drag.Sender)..", "..SerializeString(Drag.MimeType)..", "..SerializeString(Drag.Data)..", "..SerializeString(Drag.MouseIcon)..", "..SerializeString(Drag.DragIcon)..", "..Methods.Vector2(Drag.HotSpot)..")" end
function DefaultMethods.CellId(_, _, _, _, InComment) local Comment = if InComment then "=" else "" return "CellId.new(--["..Comment.."[ Undocumented ]"..Comment.."])" end

local function Serializevargs(...)
	local tbl = pack(...)
	local GenerationSize = 0
	for i = 1, #tbl do
		local Generation = Serialize(tbl[i], true, "")
		tbl[i] = Generation
		GenerationSize += #Generation
		if GenerationSize > 100000 then break end
	end
	return unpack(tbl, 1, tbl.n)
end

function Class.Convert(DataStructure, format) return Serialize(DataStructure, format, "") end
function Class.ConvertKnown(DataType, DataStructure, format) return Methods[DataType](DataStructure, format, "") end
function Class.print(...) print(Serializevargs(...)) end
function Class.warn(...) warn(Serializevargs(...)) end

-- Executors provide setclipboard globally
if type(setclipboard) == "function" then
	function Class.setclipboard(DataStructure, format)
		setclipboard(Serialize(DataStructure, format, ""))
	end
end

Class.Internals = table.freeze({ Serialize = Serialize })

return setmetatable(Class, { __tostring = function(self) return "DataToCode "..self.__VERSION end })