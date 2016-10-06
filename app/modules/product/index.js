'use strict';
angular.module('app.product', [])
  .config(['$stateProvider',
  function ($stateProvider) {
      $stateProvider
      .state('product', {
          url: '/product',
          templateUrl: 'partials/layout.html',
          redirectTo: 'product.home'
      })
      .state('product.home', {
          url: '',
          templateUrl: 'modules/product/index.html',
          controller: 'productCtrl'
      })
  }
  ])
  .controller('productCtrl', ['$scope', '$state', 'API', 'Auth', 'VarService', '$timeout',
    function ($scope, $state, API, Auth,VarService, $timeout) {
          VarService.clearAll();
    }
  ])
