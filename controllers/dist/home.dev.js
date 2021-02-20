"use strict";

/**
 * GET /
 * Home page.
 */
var User = require('../models/User');

exports.index = function (req, res) {
  res.render('home', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.loginSwitch = function (req, res) {
  res.render('loginSwitch', {
    title: 'تسجيل الدخول'
  });
};

exports.pDash = function (req, res) {
  res.render('pDashboard', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.bDash = function (req, res) {
  res.render('bDashboard', {
    title: 'منصة الاستثمار الاجتماعي'
  });
};

exports.pProfile = function (req, res) {
  User.findOne({
    id: req.params.id
  }, function (err, existingUser) {
    res.render('pProfile', {
      title: 'الملف الشخصي',
      user: existingUser
    });
  });
};

exports.bProfile = function (req, res) {
  res.render('bProfile', {
    title: 'الملف الشخصي'
  });
};

exports.offerForm = function (req, res) {
  res.render('offerForm', {
    title: 'نموذج المنح'
  });
};

exports.viewOffer = function (req, res) {
  res.render('offerView', {
    title: 'منحة مجتمعية'
  });
};

exports.postOffer = function (req, res) {};

exports.reqForm = function (req, res) {
  res.render('reqform', {
    title: 'نموذج طلب الدعم'
  });
};

exports.viewRequest = function (req, res) {
  res.render('reqView', {
    title: 'طلب دعم'
  });
};

exports.postReq = function (req, res) {};

exports.OfferApp = function (req, res) {
  res.render('bApplication', {
    title: 'التقديم على منحة'
  });
};

exports.postOfferApp = function (req, res) {};

exports.reqApp = function (req, res) {
  res.render('pApplication', {
    title: 'التقديم على طلب دعم'
  });
};

exports.postReqApp = function (req, res) {};