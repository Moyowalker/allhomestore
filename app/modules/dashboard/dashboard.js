'use strict';
angular.module('app.dashboard', [
    'ui.router'
  ])
  .config(['$stateProvider',
  function ($stateProvider) {
      $stateProvider
      .state('dashboard', {
          url: '/dashboard',
          templateUrl: 'modules/dashboard/index.html',
          controller: function($scope, $state){
             $scope.message = 'Hell Yeah!'
          }
      })
  }
])
