import { z } from 'zod'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { PrismaClient } from '@prisma/client'
import { PrismaD1 } from '@prisma/adapter-d1'
// import { basicAuth } from 'hono/basic-auth'
// import { sign, verify, jwt } from 'hono/jwt'
import { prettyJSON } from 'hono/pretty-json'
import { zValidator } from '@hono/zod-validator'
import { HTTPException } from 'hono/http-exception'

import type { JwtVariables } from 'hono/jwt'


type Variables = JwtVariables

// Binding of API credentials.
type Bindings = {
  POST_API_KEY   : string
  // JWT_SECRET: string
  // USERNAME  : string
  // PASSWORD  : string
  DB: D1Database;
}

type POSTmessage = {
  email: string;
  message: string;
}

const app = new Hono<{ Bindings: Bindings, Variables: Variables, POSTmessage:POSTmessage }>();

// Hono Logger middleware
app.use(logger());

// Formatting json for easy viewing
app.use(prettyJSON());

// Access to undefined routes
app.notFound((c) => c.json({ message: 'Not Found', ok: false }, 404));

// Is the server alive ?
app.get('/ping', (c) => { return c.json({message:'hsweb app is alive.'}, 200) });

// https://hono.dev/docs/middleware/builtin/cors
// origin: 'http://localhost:3000' -> Deno test origin
// FIX(2024/0729): Origin is hardcoded. .env.CORS_ORIGIN should be used.
// allowHeaders: ['Upgrade-Insecure-Requests'] -> Used by the client to request the server to upgrade from HTTP to HTTPS.
//                                                To enhance security, the client informs the server that it is establishing a secure connection.
// exposeHeaders: ['Content-Length'] -> Specifies the size (in bytes) of the response body. 
//                                      The client can use this information to check the integrity of the response and to indicate progress.
// Function
// It is strongly recommended that the protocol be verified to ensure a match to `$`.
// You should *never* do a forward match.
// app.use(
//   '*',
//   csrf({
//     origin: (origin) =>
//       /https:\/\/(\w+\.)?myapp\.example\.com$/.test(origin),
//   })
// )

// app.use( 
//   cors({
//     origin: 'http://localhost:8000',
//     allowHeaders: ['Authorization', 'Content-Type', 'X-API-KEY'],
//     allowMethods: ['POST', 'GET', 'OPTIONS'],
//     maxAge: 1800,
//     exposeHeaders: ['Content-Length'],
//     credentials: true,
//     }),
// );

// --------------------------------------------------------------

// Receieve messages.
// post  type : JSON { email: string, message: string }
// retun type : JSON { isSuccessful: boolean, message: string }
// 1. Check whether the URL has a valid APIKEY.
// 2. Zod Validation
//    OK -> Continue
//    Error -> Return error message."Invalid data. Please check the data and try again."
// 3. OK -> Send message to host email. return message. "Message successfully sent."
//    Error -> Return error message."Failed to send message. Please try again in a few moments."      
// 4. If all is OK, return "OK". Otherwise, return an "Error".
// Schema for receiving messages.
// Turnstile documents (server-side)
// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

const messageSchema = z.object({
  email: z.string()
    .min(1)
    .max(255)
    .email(),
  message: z.string()
    .min(10)
    .max(1000)
    .regex(/^[^<>"'\\/]*$/),
});

app.use('/sender/*', async (c, next) => {
  const apiKey = c.req.header('X-API-KEY')
  const API_KEY = c.env.POST_API_KEY
  if (apiKey !== API_KEY) {
    throw new HTTPException(403);
  }
  await next()
});

app.post(
  '/sender',
  zValidator('json', messageSchema, (result, c) => {
    if(!result.success) {
      return c.json({ isSuccessful: false, message: '不正なデータが入力されています。' }, 400);
      }
    }),
  async (c) => { 
    try {
      const adapter = new PrismaD1(c.env.DB);
      const prisma = new PrismaClient({ adapter });
      const data = await c.req.valid('json');
      
      const user = await prisma.messageHistory.create({
        data: {
          email: data.email,
          message: data.message,
        },
      });

      console.log("メッセージが届きました -> ", user);

      await prisma.$disconnect();

      return c.json({ isSuccessful: true, message: 'お問い合わせを受け付けました。' }, 200);
    } catch (error) {
      console.error(error)
      return c.json({ isSuccessful: false, message: 'サーバーが停止しています。しばらくしてからもう一度お試しください。' }, 500);
    }
  }
);

// --------------------------------------------------------------

// Login and JWT actions. 
// #1 POST Login authentication and token issuance.
// #2 GET requests, token verification.

// #1 POST Login authentication and token issuance.
// - 1. Log-in process with BASIC authentication.
// - 2. Create JWT's, set them in cookies and return them.

// sign()
// This function generates a JWT token by encoding a payload and signing it using the specified algorithm and secret.
// sign(
//   payload : unknown,
//   secret  : string,
//   alg?    : 'HS256';
//   ): Promise<string>;

// api.use('/login/*', async (c, next) => {
//   // FIX(2024/0728): hardcoded username and password
//   basicAuth({
//     username: c.env.USERNAME,
//     password: c.env.PASSWORD,
//     // realm: 'Secure Area'
//   });

//   await next();
// });

// api.get('/login', async (c) => {

//   // Create a JWT token.
//   // sub  : Identifier to uniquely identify the user
//   // role : The concept is used to determine the user's privileges and access levels within the system
//   // exp  : Indicates the expiry date of the token.
//   // FIX(2024/07/28): hardcoded payload
//   const payload = {
//     sub: '1-CXX-112',
//     role: 'guest',
//     exp: Math.floor(Date.now() / 1000) + (60 * 60) // 60min
//   }
//   const secret = c.env.JWT_SECRET
//   const token = await sign(payload, secret, "HS256");
//   return c.json(token);
// });

// #2 GET requests, token verification.
// - 1. Check the token in the cookie.
// - 2. If the token is valid, return the message "You are authorized".
// - 3. If the token is invalid, return the message "Unauthorized".

// JWT as middleware.
// https://hono.dev/docs/middleware/builtin/jwt
// Automatically validates tokens on receipt of a request, simplifying the authentication process.

// verify()
// This function checks if a JWT token is genuine and still valid.
// It ensures the token hasn't been altered and checks validity only if you added Payload Validation.

// decode()
// This function decodes a JWT token without performing signature verification.
// It extracts and returns the header and payload from the token.

// FIX: 2024/07/28 api.get -> api.use, return c.text('You are authorized')　-> GET: Retrieve data from the KVS

// api.use('/access/*', async (c, next) => {
//   const tokenToVerify = c.req.header('Authorization');
  
//   if (!tokenToVerify) {
//     console.log('Tokenless communication.');
//     throw new HTTPException(401, { message: 'Not authorised.' })
//   }

//   console.log('Token:',tokenToVerify);
//   const secret = c.env.JWT_SECRET

//   try {
//     await verify(tokenToVerify.split(' ')[1], secret);
//     await next();
//   } catch (error) {
//     console.log('Invalid token detection.:', error)
//     throw new HTTPException(401, { message: 'Not authorised.' })
//   }
// });

// api.get('/access', (c) => { return c.json('You are authorized') });

// app.route('/api', api)

export default app