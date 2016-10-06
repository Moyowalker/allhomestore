'use strict';
angular.module('app.landing', [
    'ui.router'
  ])
  .config(['$stateProvider',
  function ($stateProvider) {
      $stateProvider
      .state('landing', {
          url: '/',
          templateUrl: 'modules/landing/index.html',
          controller: 'landingCtrl'
      })
  }
  ])
  .controller('landingCtrl', ['$scope', '$state', 'API', 'Auth', 'VarService', '$timeout',
    function ($scope, $state, API, Auth,VarService, $timeout) {
          VarService.clearAll();
    }
  ])
