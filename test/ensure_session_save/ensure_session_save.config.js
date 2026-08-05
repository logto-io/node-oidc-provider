import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  deviceFlow: { enabled: true },
});

export default {
  config,
  clients: [{
    client_id: 'client',
    grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: 'none',
    application_type: 'native',
  }],
};
