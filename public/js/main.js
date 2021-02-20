/* eslint-env jquery, browser */
$(document).ready(() => {
// alert("calm down :)");
  const typed = new Typed('#typed', {
    stringsElement: '#typed-strings', loop: false, typeSpeed: 55, startDelay: 200, showCursor: false
  });

  var isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
  if (isMobile) {   document.getElementsByTagName('BODY')[0].innerHTML = '<p>please view the website from a pc browser فضلًا افتح الموقع من متصفح الحاسوب</p>'
   }
});
