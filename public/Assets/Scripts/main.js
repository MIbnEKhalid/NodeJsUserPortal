function getCookieValue(cookieName) {
    const cookies = document.cookie.split('; ');
    for (let cookie of cookies) {
        const [name, value] = cookie.split('=');
        if (name === cookieName) {
            return decodeURIComponent(value);
        }
    }
    return null; // Return null if the cookie is not found
}
function loadpage(url){
    window.location.href = url;
}