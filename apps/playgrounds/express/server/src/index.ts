import * as dotenv from "dotenv"
import express from "express"
import { ExpressAuth, ExpressAuthConfig } from "@auth/express"
import * as dotenv from "dotenv"

const authOpts: ExpressAuthConfig = {
  providers: [
    // GitHub({
    //   clientId: serverEnv.GITHUB_ID,
    //   clientSecret: serverEnv.GITHUB_SECRET,
    // }),
  ],
  debug: false,
}

async function main() {
  const app = express()

  app.get("/", (_req, res) => res.send("Server is running!"))
  app.use("/auth", ExpressAuth(authOpts))

  app.listen(5000)
}

main()
