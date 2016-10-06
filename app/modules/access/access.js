'use strict';
angular.module('app.access', [
    'ui.router', 'ngFacebook'
  ])
  .config(['$stateProvider', '$facebookProvider',
  function ($stateProvider, $facebookProvider) {
      $facebookProvider.setAppId('1503484316624984').setPermissions(['email','public_profile']); //for facebook

      $stateProvider
      .state('access', {
          abstract: true,
          url: '',
          templateUrl: 'modules/access/index.html',
      })
      .state('access.login', {
          url: '/login',
          templateUrl: 'modules/access/login.html',
          controller: 'LoginCtrl'
      })
      .state('access.signup', {
          url: '/signup',
          templateUrl: 'modules/access/signup.html',
          controller: 'LoginCtrl'
      })
  }
  ])

  /* facebook login functions */
  .run(['$rootScope', '$window', function($rootScope, $window) {
    (function(d, s, id) {
      var js, fjs = d.getElementsByTagName(s)[0];
      if (d.getElementById(id)) return;
      js = d.createElement(s); js.id = id;
      js.src = "//connect.facebook.net/en_US/sdk.js";
      fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'facebook-jssdk'));
    $rootScope.$on('fb.load', function() {
      $window.dispatchEvent(new Event('fb.load'));
    });
  }])
  //.controller('myCtrl', ['$scope', '$facebook', function($scope, $facebook) {


  /*facebook login function ends */


  .controller('LoginCtrl', ['$scope', '$state', 'Auth', 'VarService', 'API','$rootScope', '$facebook',
      function ($scope, $state, Auth, VarService, API, $rootScope, $facebook) {
        $scope.isModal = false;
        $scope.$on('fb.auth.authResponseChange', function() {
          $scope.status = $facebook.isConnected();
          $scope.fbUser = {};
          if($scope.status) {
            $facebook.api('/me?fields=id,first_name,last_name,email').then(function(user) {
              $scope.fbUser.isFbUser = true;
              $scope.fbUser.facebookID = user.id;
              $scope.fbUser.email = user.email;
              $scope.fbUser.firstName = user.first_name;
              $scope.fbUser.lastName = user.last_name;
              $scope.fbUser.password = "password";
              var userPayload = $scope.fbUser;
              var fbUserEmail = user.email;
              API.all('users').getList({email: fbUserEmail}).then(function (response){
                  if((response.length > 0) && !$scope.isModal){
                    return $scope.fblogin({email: fbUserEmail, password: "password"});
                  }else if((response.length > 0) && $scope.isModal){
                    return $scope.fbModalLogin({email: fbUserEmail, password: "password"});
                  }else if((response.length < 1) && $scope.isModal){
                    return $scope.fbModalSignup(userPayload);
                  }else{
                    return $scope.fbSignup(userPayload);
                  }
              });
            });
          }
        });

        $scope.loginToggle = function() {
          if($scope.status) {
            $facebook.logout();
          } else {
            $facebook.login();
          }
        };

        $scope.loginToggleModal = function() {
          if($scope.status) {
            $facebook.logout();
          } else {
            $scope.isModal = true;
            $facebook.login();
          }
        };


          $scope.credentials = {};
          $scope.alert = null;
          var donateInfo = VarService.all();
          $scope.login = function () {
              $scope.closeAlert();
              Auth.login($scope.credentials).then(function (res) {
                  $scope.$emit('fetchUserData', 'true');
                      $state.go('dashboard.home');
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };

          $scope.$on('modalDone', function (event, data) {
                $rootScope.user = Auth.getUser();
                // $scope.$emit('fetchUserData', 'true');
          });

          $scope.fbSignup = function (user) {
              $scope.closeAlert();
              API.all('signup').post(user).then(function (res) {
                  $scope.alert = {
                      type: 'success',
                      message: 'Account successfully created'
                  };
                  var usermail = res.email;
                  return $scope.fblogin({email: usermail, password: "password"});
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };


          $scope.fblogin = function (credentials) {
              $scope.closeAlert();
              Auth.login(credentials).then(function (res) {
                  $scope.$emit('fetchUserData', 'true');
                  $state.go('dashboard.home');
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };


          $scope.$on('modalDone', function (event, data) {
                $rootScope.user = Auth.getUser();
                // $scope.$emit('fetchUserData', 'true');
          });

          $scope.fbModalLogin = function (credentials) {
              $scope.closeAlert();
              Auth.loginModal(credentials).then(function (res) {
                  $scope.$emit('modalDone', 'true');
                      $scope.$close(true);
                      $state.go('donate.pay');
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };

          $scope.fbModalSignup = function (user) {
              $scope.closeAlert();
              API.all('signup').post(user).then(function (res) {
                  $scope.alert = {
                      type: 'success',
                      message: 'Account successfully created'
                  };
                  var usermail = res.email;
                  return $scope.fbModalLogin({email: usermail, password: "password"});
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };



          $scope.loginModal = function () {
              $scope.closeAlert();
              Auth.loginModal($scope.credentials).then(function (res) {
                  $scope.$emit('modalDone', 'true');
                      $scope.$close(true);
                      $state.go('donate.pay');
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };


        $scope.searchMail = function(){
            API.all('users').getList({email : $scope.credentials.email})
            .then(function(users){
              if(users.length > 0){
                $scope.alert = {
                      type: 'danger',
                      message: 'Email is already taken.'
                  };
              }else{
                $scope.closeAlert();
              }
            })
        }


          $scope.signup = function () {
              $scope.closeAlert();
              API.all('signup').post($scope.credentials).then(function (res) {
                  $scope.alert = {
                      type: 'success',
                      message: 'Account successfully created'
                  };
                  return $scope.login();
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };

          $scope.signupModal = function () {
              $scope.closeAlert();
              API.all('signup').post($scope.credentials).then(function (res) {
                  $scope.alert = {
                      type: 'success',
                      message: 'Account successfully created'
                  };
                  return $scope.loginModal();
              }, function (error) {
                  $scope.alert = {
                      type: 'danger',
                      message: error.data.response.message
                  };
              });
          };

          $scope.closeAlert = function () {
              $scope.alert = null;
          };
      }
  ])
