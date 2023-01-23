'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);
  entities.forEach((entity) => {
    const url = options.url.endsWith('/') ? options.url : `${options.url}/`;

    let requestOptions = {
      method: 'POST',
      uri: `${url}api/oti/v1/host/reputation`,
      qs: {
        authkey: options.apiKey,
        host: entity.value
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function(done) {
      requestWithDefaults(requestOptions, function(error, res, body) {
        Logger.trace({ body, status: res.statusCode });
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        if (
          !options.showUnrated &&
          result.body.threatData &&
          result.body.threatData.verdict === 'Unrated, No Intel Found'
        ) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else if (!options.showBenign && result.body.threatData && result.body.threatData.verdict === 'Benign') {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: _getSummaryTags(result.body),
              details: result.body
            }
          });
        }
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function _getSummaryTags(body){
  let tags = [];

  tags.push(body.threatData.verdict);

  if(body && body.threatData && body.threatData.threatStatus !== 'N/A'){
    tags.push(body.threatData.threatStatus);
  }

  if(body && body.threatData && body.threatData.threatName !== 'N/A'){
    tags.push(body.threatData.threatName);
  }

  return tags;
}

function doReportLookup(entity, options) {
  return function(done) {
    const url = options.url.endsWith('/') ? options.url : `${options.url}/`;
    let requestOptions = {
      method: 'POST',
      uri: `${url}api/oti/v1/host/report`,
      qs: {
        authkey: options.apiKey,
        host: entity.value,
        page: '1',
        rpp: options.maxRecords
      },
      json: true
    };

    request(requestOptions, (error, response, body) => {
      let processedResult = handleRestError(error, entity, response, body);

      if (processedResult.error) {
        done(processedResult);
        return;
      }

      done(null, processedResult.body);
    });
  };
}

function onDetails(lookupObject, options, cb) {
  async.parallel(
    {
      report: doReportLookup(lookupObject.entity, options)
    },
    (err, results) => {
      if (err) {
        return cb(err);
      }
      //store the results into the details object so we can access them in our template
      lookupObject.data.details.report = results.report;

      Logger.trace({ lookup: lookupObject.data }, 'Looking at the data after on details.');

      cb(null, lookupObject.data);
    }
  );
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error || !body) {
    return {
      error,
      body,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode !== 200) {
    return {
      error: 'Did not receive HTTP 200 Status Code',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred'
    };
  }

  if (res.statusCode === 200 && body.errorNo === 0) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else {
    result = {
      body,
      errorNumber: body.errorNo,
      error: body.errorMsg,
      detail: body.errorMsg
    };
  }

  return result;
}

module.exports = {
  doLookup: doLookup,
  onDetails: onDetails,
  startup: startup
};
