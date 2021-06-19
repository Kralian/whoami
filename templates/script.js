async function updateinfo(url,tag){
  console.log(url);
  var text = "unknown..";
    await fetch(url)
    .then(response => response.json())
    .then(info => {
        console.log(" Info is "+info.IP);
        text = "address is: "+info.IP;
    })
    .catch((error) => {
      console.error('Error:', error);
      text = "link unavailable";
    });
    document.getElementById(tag).textContent = text;
}; 

async function geosuccess(position) {
  console.log(position);
  let lat = position.coords.latitude;
  let lon = position.coords.longitude;
  let accuracy = position.coords.accuracy;
  /*
  console.log(position.coords.altitude);
  console.log(position.coords.altitudeAccuracy);
  console.log(position.coords.heading);
  console.log(position.coords.speed);
  */
  let text = `${lat}° ${lon}° ${accuracy}m`;
  document.getElementById('extrainfo').textContent = text;
}

async function geofailure(reason) {
  let text = `Failed because: ${reason}`;
  console.log(`Failed because: ${reason}`)
  document.getElementById('extrainfo').textContent = text;
}

window.addEventListener('DOMContentLoaded', (event) => {
  console.log(`Event caught : ${event}`);
  // ipv4 versions
  let v4url = '{{ info.scheme }}://{{ info.v4host }}/json';
  let v4tag = 'v4info';
  // ipv6 versions
  let v6url = '{{ info.scheme }}://{{ info.v6host }}/json';
  let v6tag = 'v6info';
  updateinfo(v4url,v4tag);
  updateinfo(v6url,v6tag);
  var geooptions = {
    enableHighAccuracy: true,
    timeout: 5000,
    maximumAge: 0
  };
  //navigator.geolocation.getCurrentPosition(geosuccess,geofailure,geooptions);
})