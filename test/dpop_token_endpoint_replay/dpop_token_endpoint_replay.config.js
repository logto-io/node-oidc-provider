import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  dPoP: { enabled: true },
  clientCredentials: { enabled: true },
});

export default {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
