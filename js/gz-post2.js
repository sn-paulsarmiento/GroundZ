
/* UX pass: account out of the section nav, tab icons, current view on <body> */
(function(){
  function $(i){return document.getElementById(i)}
  var I={
    Rank:'<path d="M8 21h8M12 17v4M7 4h10v5a5 5 0 0 1-10 0V4z"/><path d="M17 5h3v2a3 3 0 0 1-3 3M7 5H4v2a3 3 0 0 0 3 3"/>',
    Tour:'<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 2v4M16 2v4"/>',
    Cards:'<rect x="4" y="3" width="12" height="17" rx="2"/><path d="M8 3.5 18.5 5.6a2 2 0 0 1 1.6 2.3l-2.3 11.5"/>',
    Tools:'<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-.5-.5-2.5z"/>',
    Pro:'<path d="m12 3 2.6 5.6 6.1.7-4.5 4.2 1.2 6L12 16.6 6.6 19.5l1.2-6L3.3 9.3l6.1-.7z"/>'
  };
  if(location.hash==="#privacy")setTimeout(showPrivacy,300);if(location.hash==="#terms")setTimeout(showTerms,300);if(location.hash==="#report")setTimeout(function(){showReport()},300);
  ["Rank","Tour","Cards","Tools","Pro"].forEach(function(k){var b=$("t"+k);if(!b)return;var s=document.createElement("span");s.className="ti";s.setAttribute("aria-hidden","true");s.innerHTML='<svg viewBox="0 0 24 24">'+I[k]+'</svg>';b.insertBefore(s,b.firstChild)});
  var tb=document.querySelector(".topbar-in"),th=$("themeBtn"),a=document.createElement("div");a.className="acct";
  ["tDash","tAcct"].forEach(function(i){var b=$(i);if(b)a.appendChild(b)});tb.insertBefore(a,th);
  var V=["Rank","Tour","Dash","Acct","Deck","Pro","Cards","Tools"];
  function sync(){for(var i=0;i<V.length;i++){var e=$("v"+V[i]);if(e&&!e.hidden){document.body.setAttribute("data-view",V[i]);return}}}
  sync();var mo=new MutationObserver(sync);V.forEach(function(k){var e=$("v"+k);if(e)mo.observe(e,{attributes:true,attributeFilter:["hidden"]})});
})();
