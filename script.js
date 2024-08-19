const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
}

const sha256 = async (plain) => {
   const encoder = new TextEncoder()
   const data = encoder.encode(plain)
   return window.crypto.subtle.digest('SHA-256', data)
}

const base64encode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
}

document.getElementById('auth-button').addEventListener('click', authenticateWithSpotify);
document.getElementById('fetch-button').addEventListener('click', fetchTopArtists);

const clientId = 'a4d2dbad912341e7a2f44213568fb4a2';
const redirectUri = 'https://jc1125.github.io/basicometer/';

const scope = 'user-read-private user-read-email';
const authUrl = new URL("https://accounts.spotify.com/authorize")
const codeVerifier  = generateRandomString(64);
window.localStorage.setItem('code_verifier', codeVerifier);

async function authenticateWithSpotify() {
    
    const hashed = await sha256(codeVerifier)
    const codeChallenge = base64encode(hashed);

    // generated in the previous step
    const params =  {
    response_type: 'code',
    client_id: clientId,
    scope,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
    redirect_uri: redirectUri,
    }

    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
}

async function fetchTopArtists() {
    // Fetch top artists logic here
    const urlParams = new URLSearchParams(window.location.search);
    let code = urlParams.get('code');

    const getToken = async code => {

        // stored in the previous step
        let codeVerifier = localStorage.getItem('code_verifier');
      
        const payload = {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            client_id: clientId,
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            code_verifier: codeVerifier,
          }),
        }
      
        const body = await fetch(url, payload);
        const response =await body.json();
      
        localStorage.setItem('access_token', response.access_token);
    }

    await getToken(code)

    console.log("Token:")
    console.log(localStorage.getItem('access_token'))
}