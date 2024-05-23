exports.handler = async (event) => {
      try {   
        const REACT_APP_SIGNATURE_PRIVATE_KEY = {
          kty: "EC",
          d: "0GlHbGc8vSnyiB-Lf4_im_WFwrxM0MJjkk96o1-K3JQ",
          crv: "P-256",
          x: "wg11s6ZpBc0my5gT-mYatTZRDhgStyd_0qARVBwAWa4",
          y: "hlVoYWwlCuTMnm79Ppmf3RslIwDRhqdCCnm01PkhA2s"
        };
        const REACT_APP_ENCRYPTION_PRIVATE_KEY =  {
          kty: "EC",
          d: "p4YZHS0_BS4VMUayEtt38qi2sMdkhs4JRFlks7HJCD8",
          crv: "P-256",
          x: "0GR5oBa1FINjCZP_W-nR8Yqoz4E_9j7lgCuRPh9PZTA",
          y: "0leGfxdQSJdtubopqhj5uhPVYV3LSd_yf3y2DdRD5No"
        }
    REACT_APP_CLIENT_ID="tLRDBkf1CNy5Rsi34mEKuOD5EpQAwjIq"
    REACT_APP_JWTTOKENURL="https://stg-id.singpass.gov.sg"
    REACT_APP_SPTOKENURL="https://stg-id.singpass.gov.sg/token"
    REACT_APP_KID="testing123"
    REACT_APP_REDIRECT_URI="https://singpassdemoapp.netlify.app/callback"     
        const code =event.queryStringParameters.code;
        console.log(code);
        const jose = require("jose");
        const moment = require("moment");
        const axios = require("axios");
        const alg = "ES256";
        //Signature Keys
        const privateKey = await jose.importJWK(REACT_APP_SIGNATURE_PRIVATE_KEY, alg);
        const nowTime = moment().unix();
        const futureTime = moment().add(2, "minutes").unix();
        const jwt = await new jose.SignJWT({
          sub: REACT_APP_CLIENT_ID,
          iss: REACT_APP_CLIENT_ID,
          aud: REACT_APP_JWTTOKENURL,
          iat: nowTime,
          exp: futureTime,
        })
          .setProtectedHeader({
            alg: "ES256",
            kid: REACT_APP_KID,
            typ: "JWT",
          })
          .sign(privateKey);
       console.log(jwt);
       const url = REACT_APP_SPTOKENURL;
        const { data } = await axios.post(
          url,
          new URLSearchParams({
            client_id: REACT_APP_CLIENT_ID,
            redirect_uri: REACT_APP_REDIRECT_URI,
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
        if (e.response?.data) {
          console.log(e.response.data);
          }
       return {
         statusCode: 500,
          body: JSON.stringify({ data: e }),
          headers: {
            "Content-Type": "application/json",
          }, 
        }; 

      }
    
  
    
  }
