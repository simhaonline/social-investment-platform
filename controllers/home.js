/**
 * GET /
 * Home page.
 */
const User = require('../models/User');

exports.index = (req, res) => {
  res.render('home', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.loginSwitch = (req, res) => {
  res.render('loginSwitch', {
    title: 'تسجيل الدخول'
  });
};

exports.pDash = (req, res) => {
  res.render('pDashboard', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.bDash = (req, res) => {
  res.render('bDashboard', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.pProfile = (req, res) => {
  User.findOne({ id: req.params.id }, (err, existingUser) => {
    res.render('pProfile', {
      title: 'الملف الشخصي',
      user: existingUser
    });
  });
};

exports.bProfile = (req, res) => {
  res.render('bProfile', {
    title: 'الملف الشخصي'
  });
};

exports.offerForm = (req, res) => {
  res.render('offerForm', {
    title: 'نموذج المنح'
  });
};

exports.viewOffer = (req, res) => {
  res.render('offerView', {
    title: 'منحة مجتمعية'
  });
};

exports.postOffer = (req, res) => {
 
};

exports.reqForm = (req, res) => {
  res.render('reqform', {
    title: 'نموذج طلب الدعم'
  });
};

exports.viewRequest = (req, res) => {
  res.render('reqView', {
    title: 'طلب دعم'
  });
};

exports.postReq = (req, res) => {
 
};

exports.OfferApp = (req, res) => {
  res.render('bApplication', {
    title: 'التقديم على منحة'
  });
};

exports.postOfferApp = (req, res) => {

};

exports.reqApp = (req, res) => {
  res.render('pApplication', {
    title: 'التقديم على طلب دعم'
  });
};

exports.postReqApp = (req, res) => {
 
};