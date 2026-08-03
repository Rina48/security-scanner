import { loadServerConfig } from "./security/serverConfig.js";

const config = loadServerConfig();
const { createApp } = await import("./app.js");
const app = createApp(config);

app.listen(config.port, config.bindHost, () => {
  console.log(
    `Security Scanner API is running at http://${config.bindHost}:${config.port}`,
  );
});
