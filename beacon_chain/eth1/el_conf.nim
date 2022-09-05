import
  std/[options, strutils, uri],
  stew/results, chronicles, confutils,
  json_serialization, # for logging
  toml_serialization, toml_serialization/lexer,
  ../spec/engine_authentication

type
  EngineApiRole* = enum
    DepositSyncing = "sync-deposits"
    BlockValidation = "validate-blocks"
    BlockProduction = "produce-blocks"

  EngineApiRoles* = set[EngineApiRole]

  EngineApiUrl* = object
    url: string
    jwtSecret: Option[seq[byte]]
    roles: EngineApiRoles

  EngineApiUrlConfigValue* = object
    url*: string # TODO: Use the URI type here
    jwtSecret*: Option[string]
    jwtSecretFile*: Option[InputFile]
    roles*: Option[EngineApiRoles]

const defaultEngineApiRoles* = { DepositSyncing, BlockValidation, BlockProduction }

chronicles.formatIt EngineApiUrl:
  it.url

proc init*(T: type EngineApiUrl,
           url: string,
           jwtSecret = none seq[byte],
           roles = defaultEngineApiRoles): T =
  T(url: url, jwtSecret: jwtSecret, roles: roles)

func url*(engineUrl: EngineApiUrl): string =
  engineUrl.url

func jwtSecret*(engineUrl: EngineApiUrl): Option[seq[byte]] =
  engineUrl.jwtSecret

func roles*(engineUrl: EngineApiUrl): EngineApiRoles =
  engineUrl.roles

func unknownRoleMsg(role: string): string =
  "'" & role & "' is not a valid EL function"

template raiseError(reader: var TomlReader, msg: string) =
  raiseTomlErr(reader.lex, msg)

template raiseError(reader: var JsonReader, msg: string) =
  raiseTomlErr(reader.lex, msg)

proc readValue*(reader: var TomlReader, value: var EngineApiRoles)
               {.raises: [Defect, SerializationError, IOError].} =
  let roles = reader.readValue seq[string]
  if roles.len == 0:
    reader.raiseError "At least one role should be provided"
  for role in roles:
    case role.toLowerAscii
    of $DepositSyncing:
      value.incl DepositSyncing
    of $BlockValidation:
      value.incl BlockValidation
    of $BlockProduction:
      value.incl BlockProduction
    else:
      reader.raiseError(unknownRoleMsg role)

proc writeValue*(writer: var JsonWriter, roles: EngineApiRoles)
                {.raises: [Defect, SerializationError, IOError].} =
  var strRoles: seq[string]

  for role in EngineApiRole:
    if role in roles: strRoles.add $role

  writer.writeValue strRoles

# `decodeQuery` was introduced in Nim 1.4
when not declared(decodeQuery):
  # TODO
  # This is a verbatim copy of the iterator from Nim's std library.
  # We can remove it from the code once we stop supporting Nim 1.2.
  iterator decodeQuery*(data: string, sep = '&'): tuple[key, value: string] =
    ## Reads and decodes the query string `data` and yields the `(key, value)` pairs
    ## the data consists of. If compiled with `-d:nimLegacyParseQueryStrict`,
    ## a `UriParseError` is raised when there is an unencoded `=` character in a decoded
    ## value, which was the behavior in Nim < 1.5.1.
    runnableExamples:
      import std/sequtils
      assert toSeq(decodeQuery("foo=1&bar=2=3")) == @[("foo", "1"), ("bar", "2=3")]
      assert toSeq(decodeQuery("foo=1;bar=2=3", ';')) == @[("foo", "1"), ("bar", "2=3")]
      assert toSeq(decodeQuery("&a&=b&=&&")) == @[("", ""), ("a", ""), ("", "b"), ("", ""), ("", "")]

    proc handleHexChar(c: char, x: var int): bool {.inline.} =
      ## Converts `%xx` hexadecimal to the ordinal number and adds the result to `x`.
      ## Returns `true` if `c` is hexadecimal.
      ##
      ## When `c` is hexadecimal, the proc is equal to `x = x shl 4 + hex2Int(c)`.
      runnableExamples:
        var x = 0
        assert handleHexChar('a', x)
        assert x == 10

        assert handleHexChar('B', x)
        assert x == 171 # 10 shl 4 + 11

        assert not handleHexChar('?', x)
        assert x == 171 # unchanged
      result = true
      case c
      of '0'..'9': x = (x shl 4) or (ord(c) - ord('0'))
      of 'a'..'f': x = (x shl 4) or (ord(c) - ord('a') + 10)
      of 'A'..'F': x = (x shl 4) or (ord(c) - ord('A') + 10)
      else:
        result = false

    proc decodePercent(s: openArray[char], i: var int): char =
      ## Converts `%xx` hexadecimal to the character with ordinal number `xx`.
      ##
      ## If `xx` is not a valid hexadecimal value, it is left intact: only the
      ## leading `%` is returned as-is, and `xx` characters will be processed in the
      ## next step (e.g. in `uri.decodeUrl`) as regular characters.
      result = '%'
      if i+2 < s.len:
        var x = 0
        if handleHexChar(s[i+1], x) and handleHexChar(s[i+2], x):
          result = chr(x)
          inc(i, 2)

    proc parseData(data: string, i: int, field: var string, sep: char): int =
      result = i
      while result < data.len:
        let c = data[result]
        case c
        of '%': add(field, decodePercent(data, result))
        of '+': add(field, ' ')
        of '&': break
        else:
          if c == sep: break
          else: add(field, data[result])
        inc(result)

    var i = 0
    var name = ""
    var value = ""
    # decode everything in one pass:
    while i < data.len:
      setLen(name, 0) # reuse memory
      i = parseData(data, i, name, '=')
      setLen(value, 0) # reuse memory
      if i < data.len and data[i] == '=':
        inc(i) # skip '='
        when defined(nimLegacyParseQueryStrict):
          i = parseData(data, i, value, '=')
        else:
          i = parseData(data, i, value, sep)
      yield (name, value)
      if i < data.len:
        when defined(nimLegacyParseQueryStrict):
          if data[i] != '&':
            uriParseError("'&' expected at index '$#' for '$#'" % [$i, data])
        inc(i)

proc parseCmdArg*(T: type EngineApiUrlConfigValue, input: string): T
                 {.raises: [ValueError, Defect].} =
  var
    uri = parseUri(input)
    jwtSecret: Option[string]
    jwtSecretFile: Option[InputFile]
    roles: Option[EngineApiRoles]

  if uri.anchor != "":
    for key, value in decodeQuery(uri.anchor):
      case key
      of "jwtSecret":
        jwtSecret = some value
      of "jwtSecretFile":
        jwtSecretFile = some InputFile.parseCmdArg(value)
      of "roles":
        var uriRoles: EngineApiRoles = {}
        for role in split(value, ","):
          case role.toLowerAscii
          of $DepositSyncing:
            uriRoles.incl DepositSyncing
          of $BlockValidation:
            uriRoles.incl BlockValidation
          of $BlockProduction:
            uriRoles.incl BlockProduction
          else:
            raise newException(ValueError, unknownRoleMsg role)
        if uriRoles == {}:
          raise newException(ValueError, "The list of roles should not be empty")
        roles = some uriRoles
      else:
        raise newException(ValueError, "'" & key & "' is not a recognized Engine URL property")
    uri.anchor = ""

  EngineApiUrlConfigValue(
    url: $uri,
    jwtSecret: jwtSecret,
    jwtSecretFile: jwtSecretFile,
    roles: roles)

proc toFinalUrl*(confValue: EngineApiUrlConfigValue,
                 defaultJwtSecret: Option[seq[byte]]): Result[EngineApiUrl, cstring] =
  if confValue.jwtSecret.isSome and confValue.jwtSecretFile.isSome:
    return err "The options `jwtSecret` and `jwtSecretFile` should not be specified together"

  let jwtSecret = if confValue.jwtSecret.isSome:
    some(? parseJwtTokenValue(confValue.jwtSecret.get))
  elif confValue.jwtSecretFile.isSome:
    some(? loadJwtSecretFile(confValue.jwtSecretFile.get))
  else:
    none seq[byte]

  ok EngineApiUrl.init(
    url = confValue.url,
    jwtSecret = jwtSecret,
    roles = confValue.roles.get(defaultEngineApiRoles))

proc loadJwtSecret*(jwtSecret: Option[InputFile]): Option[seq[byte]] =
  if jwtSecret.isSome:
    let res = loadJwtSecretFile(jwtSecret.get)
    if res.isOk:
      some res.value
    else:
      fatal "Failed to load JWT secret file", err = res.error
      quit 1
  else:
    none seq[byte]

proc toFinalEngineApiUrls*(elUrls: seq[EngineApiUrlConfigValue],
                           defaultJwtSecret: Option[InputFile]): seq[EngineApiUrl] =
  let jwtSecret = loadJwtSecret defaultJwtSecret

  for elUrl in elUrls:
    let engineApiUrl = elUrl.toFinalUrl(jwtSecret).valueOr:
      fatal "Invalid EL configuration", err = error
      quit 1
    result.add engineApiUrl

proc fixupWeb3Urls*(web3Url: var string) =
  var normalizedUrl = toLowerAscii(web3Url)
  if not (normalizedUrl.startsWith("https://") or
          normalizedUrl.startsWith("http://") or
          normalizedUrl.startsWith("wss://") or
          normalizedUrl.startsWith("ws://")):
    warn "The Web3 URL does not specify a protocol. Assuming a WebSocket server", web3Url
    web3Url = "ws://" & web3Url
