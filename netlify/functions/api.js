/* 
exports.handler = async (event, context) => {
    if (event.httpMethod === 'POST') {
      try {
        const code = event.queryStringParameters.code;
        const jose = require("jose");
        const moment = require("moment");
        const axios = require("axios");
        const alg = "ES256";
        //Signature Keys
        const jwk = process.env.REACT_APP_SIGNATURE_PRIVATE_KEY
    
        const privateKey = await jose.importJWK(jwk, alg);
        const nowTime = moment().unix();
        const futureTime = moment().add(2, "minutes").unix();
        const jwt = await new jose.SignJWT({
          sub: process.env.REACT_APP_CLIENT_ID,
          iss: process.env.REACT_APP_CLIENT_ID,
          aud: process.env.REACT_APP_STGENV_TOKENURL,
          iat: nowTime,
          exp: futureTime,
        })
          .setProtectedHeader({
            alg: "ES256",
            kid: process.env.REACT_APP_KID,
            typ: "JWT",
          })
          .sign(privateKey);
    
        // console.log(jwt);
    
        const url = "https://stg-id.singpass.gov.sg/token";
        const { data } = await axios.post(
          url,
          new URLSearchParams({
            client_id: process.env.REACT_APP_CLIENT_ID,
            redirect_uri: process.env.REACT_APP_REDIRECT_URI,
            code: code,
            client_assertion_type:
              "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            grant_type: "authorization_code",
            client_assertion: jwt,
          }),
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        console.log(data);
        // console.log(typeof data);
        //Enc Keys
        try {
          const descprivateKey = {
            kty: "EC",
            d: "p4YZHS0_BS4VMUayEtt38qi2sMdkhs4JRFlks7HJCD8",
            crv: "P-256",
            x: "0GR5oBa1FINjCZP_W-nR8Yqoz4E_9j7lgCuRPh9PZTA",
            y: "0leGfxdQSJdtubopqhj5uhPVYV3LSd_yf3y2DdRD5No",
          };
    
          const privateKey2 = await jose.importJWK(
            descprivateKey,
            "ECDH-ES+A256KW"
          );
          const { plaintext } = await jose.compactDecrypt(
            data.id_token,
            privateKey2
          );
          const dto = new TextDecoder().decode(plaintext);
          const result = await jose.decodeJwt(dto);
          const NRIC = result.sub.substring(2, 11);
          console.log(NRIC);
          // return new Response("Youre visiting");
          //Return NRIC
          return {
            statusCode: 200,
            body: JSON.stringify({ data: NRIC }),
            headers: {
              "Content-Type": "application/json",
            },
          };
          //Return error
        } catch (e) {
          console.log(e);
        }
      } catch (e) {
        return {
          statusCode: 500,
          body: JSON.stringify({ data: e }),
          headers: {
            "Content-Type": "application/json",
          },
        };
      }
     }
    }
    
  
     */

    exports.handler = async (event, context) => {
        if (event.httpMethod === 'POST') {
          try {
            // Parse the incoming JSON payload from the request body
            const requestBody = JSON.parse(event.body);
      
            // Save the data to a database or perform other necessary operations
            // ...
      
            // Return a success response
            return {
              statusCode: 200,
              body: JSON.stringify({ message: 'POST request processed successfully' }),
            };
          } catch (error) {
            // Return an error response if there was an issue processing the request
            return {
              statusCode: 400,
              body: JSON.stringify({ error: 'Failed to process POST request' }),
            };
          }
        }
      };