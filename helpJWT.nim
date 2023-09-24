
import jwt, times, json, tables

const secret = "65073f81ac36f0aeb7305d72.65073f87224972385a0f36f4.1694973808.abcdefghijklmnopqrstu.1234567890"

# change object proc signJWT*(newType: NewObjek): string =
proc signJWT*(uuid, email, name: string): string =
  var token = toJWT(%*{
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "claims": {
      "uuid": uuid,
      "email": email,
      "name": name,
      "exp": (getTime() + 100.days).toUnix() # 100 day exp
    }
  })
  token.sign(secret)
  result = $token

proc verifyJWT*(token: string): bool =
  try:
    let jwtToken = token.toJWT()
    result = jwtToken.verify(secret, HS256)
  except InvalidToken:
    result = false

proc decodeJWT*(token: string): string =
  let jwt = token.toJWT()
  result = $jwt.claims["uuid"].node.str  
