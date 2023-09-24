
import jwt, json

const secret = "65073f81ac36f0aeb7305d72.65073f87224972385a0f36f4.1694973808.abcdefghijklmnopqrstu.1234567890"

proc signJWT*(data: string): string =
  # load data to Json
  let newData = parseJson(data)
  let token = toJWT(%*{
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "claims": newData
  })
  token.sign(secret)
  result = $token

proc verifyJWT*(token: string): bool =
  try:
    let jwtToken = token.toJWT()
    result = jwtToken.verify(secret, HS256)
  except InvalidToken:
    result = false

#need update
proc decodeJWT*(token: string): string =
  let jwt = token.toJWT()
  result = $jwt.claims["uuid"].node.str  
