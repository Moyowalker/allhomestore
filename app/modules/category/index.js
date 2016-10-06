'use strict';
angular.module('app.category', [])
  .config(['$stateProvider',
  function ($stateProvider) {
      $stateProvider
      .state('category', {
          url: '/category',
          templateUrl: 'modules/category/index.html',
          controller: 'categoryCtrl'
      })
  }
  ])
  .controller('categoryCtrl', ['$scope', '$state', 'API', 'Auth', 'VarService', '$timeout',
    function ($scope, $state, API, Auth,VarService, $timeout) {
          VarService.clearAll();
    }
  ])
