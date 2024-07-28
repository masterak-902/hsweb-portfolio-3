import { Hono } from 'hono'
import { z } from 'zod'
import { logger } from 'hono/logger'
import { basicAuth } from 'hono/basic-auth'
import { HTTPException } from 'hono/http-exception'
import { prettyJSON } from 'hono/pretty-json'
import { zValidator } from '@hono/zod-validator'
import { jwt } from 'hono/jwt'
import { cors } from 'hono/cors'

const app = new Hono();

// Hono Logger middleware
app.use(logger());

// Formatting json for easy viewing
app.use(prettyJSON());

// Access to undefined routes
app.notFound((c) => c.json({ message: 'Not Found', ok: false }, 404));

// Is the server alive ?
app.get('/ping', (c) => { return c.text('hsweb api is alive.') });

// Binding of API credentials.
type Bindings = {
  API_KEY: string
  SECRET_KEY: string
  USERNAME: string
  PASSWORD: string
}

const api = new Hono<{ Bindings: Bindings }>();

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
//Schema for receiving messages.

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

api.use('/sender/*', async (c, next) => {
  const apiKey = c.req.header('X-API-KEY')
  const API_KEY = c.env.API_KEY
  if (apiKey !== API_KEY) {
    throw new HTTPException(403, { message: 'Forbidden' })
  }

  await next()

  });

api.post(
  '/sender',
  zValidator('json', messageSchema, (result, c) => {
    if(!result.success) {
      return c.json( { isSuccessful:'false', message: 'Invalid data. Please check the data and try again.' }, 400) 
      }
    }),
  async (c) => { 
    try {
      const data = c.req.valid('json')
      console.log(data.email, data.message);
      // TODO(2024/07/27) Sending email method.
      return c.json({ isSuccessful:'true', message: 'Message successfully sent.' }, 200);
    } catch (error) {
      console.error(error)
      return c.json({ isSuccessful:'false', message: 'Failed to send message. Please try again in a few moments.' }, 500);
    }
    
    });

// --------------------------------------------------------------

// Login and JWT actions. 
// #1 POST Login authentication and token issuance.
// #2 GET requests, token verification.

// #1 POST Login authentication and token issuance.
// - 1. Log-in process with BASIC authentication.
// - 2. 
api.use('/auth/*', cors());

api.post('/auth',
  basicAuth({
    username: 'hono',
    password: 'acoolproject'
  }),
  async (c) => {
    return c.text('You are authorized');
  }
);

app.route('/api', api)

export default app


