const TIERS = {0:"D", 1:"C", 2:"B", 3:"A", 4:"S", 5:"Inhumanly Basic"}

function resetLocal() {
    localStorage.clear()
}

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
document.getElementById('reset').addEventListener('click', resetLocal);

const clientId = 'a4d2dbad912341e7a2f44213568fb4a2';
const redirectUri = 'https://jc1125.github.io/basicometer/';

const scope = 'user-read-private user-read-email';
const authUrl = new URL("https://accounts.spotify.com/authorize")

if (!window.localStorage.getItem('code_verifier')){
    let codeVerifier  = generateRandomString(64);
    window.localStorage.setItem('code_verifier', codeVerifier);
}

async function authenticateWithSpotify() {
    
    const codeVerifier = window.localStorage.getItem('code_verifier')
    const hashed = await sha256(codeVerifier)
    const codeChallenge = base64encode(hashed);

    // generated in the previous step
    const params =  {
    response_type: 'code',
    client_id: clientId,
    scope: "user-top-read",
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
    redirect_uri: redirectUri,
    }

    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();
}

async function fetchTopArtists() {
    // Auth if needed
    if (!window.localStorage.getItem("access_token") || window.localStorage.getItem("access_token") == "undefined"){
        const urlParams = new URLSearchParams(window.location.search);
        let code = urlParams.get('code');

        // stored in the previous step
        let codeVerifier = localStorage.getItem('code_verifier');

        const tokenUrl = new URL("https://accounts.spotify.com/api/token")
        
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
        
        const body = await fetch(tokenUrl, payload);
        const response =await body.json();
        
        localStorage.setItem('access_token', response.access_token);
    }
    token = window.localStorage.getItem("access_token")

    // Get top song data
    const payload = {
        method: 'GET',
        headers: {
        'Authorization': 'Bearer ' + token,
        }
    }
    
    response_vals = []
    
    let body1 = await fetch('https://api.spotify.com/v1/me/top/artists?time_range=long_term&limit=50&offset=0', {headers: {Authorization: 'Bearer ' + token}});
    let response1 =await body1.json();
    response_vals.push(response1)

    let total_artists = response1.total
    let remaining = total_artists - 50
    let iters = Math.floor(remaining / 50)

    for(let i = 0; i <= iters; i++) {
        offset = 50 * (i+1)
        let body2 = await fetch('https://api.spotify.com/v1/me/top/artists?time_range=long_term&limit=50&offset='+offset, {headers: {Authorization: 'Bearer ' + token}});
        let response2 = await body2.json();
        response_vals.push(response2)
    }

    let cumu_pop = 0
    for (r of response_vals) {
        for (item of r.items) {
            cumu_pop += item.popularity
            // p = document.createElement('p')
            // p.innerText = "[Name] " + item.name + " [Popularity]: " + item.popularity
            // document.getElementById('result2').appendChild(p)
        }
    }

    avg_pop = Math.floor(cumu_pop / total_artists)

    document.getElementById('result-text').innerText = "Your taste is " + TIERS[Math.floor(avg_pop/20)] + " tier basic based on your top "+total_artists+" artists with an average popularity of " + avg_pop

}