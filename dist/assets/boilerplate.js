angular.module('app.filters', []);

angular.module('app.accessService', [])
  .constant('AccessLevel', {
    anon: 0,
    user: 1,
    admin: 2
  });

angular.module('app.authService', [])
    .factory('Auth', ['$http', 'LocalService', 'API', '$q', 'AccessLevel',
        function ($http, LocalService, API, $q, AccessLevel) {
            return {
                 authorize: function (access) {
                    if (access === AccessLevel.user) {
                        return this.isAuthenticated();
                    } else {
                        return true;
                    }
                },
                isAuthenticated: function () {
                    return LocalService.get('auth_token');
                },
                login: function (credentials) {
                    var deferred = $q.defer();
                    API.all('login').post(credentials).then(function (data) {
                        LocalService.set('auth_token', JSON.stringify(data));
                        deferred.resolve(data);
                    }, function (error) {
                        deferred.reject(error);
                    });

                    return deferred.promise;
                },
                loginModal: function (credentials) {
                    var deferred = $q.defer();
                    API.all('login').post(credentials).then(function (data) {
                        LocalService.set('auth_token', JSON.stringify(data));
                        deferred.resolve(data);
                    }, function (error) {
                        deferred.reject(error);
                    });

                    return deferred.promise;
                },
                save: function (credentials) {
                    var defer = $q.defer();
                    LocalService.set('auth_token', JSON.stringify(credentials));
                    defer.resolve("");
                    return defer.promise;
                },
                logout: function () {
                    // The backend doesn't care about logouts, delete the token and you're good to go.
                    LocalService.unset('auth_token');
                },
                getUser: function () {
                    if (LocalService.get('auth_token')) {
                        return angular.fromJson(LocalService.get('auth_token')).user;
                    } else {
                        return false;
                    }
                },
                updateUser: function(user) {
                    var current = angular.fromJson(LocalService.get('auth_token'));
                    var update = {token: current.token, user: user}
                    this.save(update)
                }
            }
        }
    ])
    .factory('AuthInterceptor', ['$q', '$injector', 'LocalService','VarService',
        function ($q, $injector, LocalService, VarService) {
            return {
                request: function (config) {
                    var token;
                    if (LocalService.get('auth_token')) {
                        token = angular.fromJson(LocalService.get('auth_token')).token;
                    }
                    if (token) {
                        config.headers.Authorization = 'Bearer ' + token;
                    }
                    return config;
                },
                responseError: function (response) {
                    if (response.status === 401 || response.status === 403) {
                        LocalService.unset('auth_token');
                        var donateInfo = VarService.all();
                        if(donateInfo.length < 1){
                            $injector.get('$state').go('access.login');
                        }
                    }
                    return $q.reject(response);
                }
            }
        }
    ])
    .config(['$httpProvider',
        function ($httpProvider) {
            $httpProvider.interceptors.push('AuthInterceptor');
        }
    ]);

angular.module('app.localService', [])
    .factory('LocalService', function () {
        return {
            get: function (key) {
                return localStorage.getItem(key);
            },
            set: function (key, val) {
                return localStorage.setItem(key, val);
            },
            unset: function (key) {
                return localStorage.removeItem(key);
            }
        }
    });

'use strict';
angular.module('app.services', ['app.accessService', 'app.authService', 'app.localService', 'app.varService', 'ui.load']);

'use strict';

/**
 * 0.1.1
 * Deferred load js/css file, used for ui-jq.js and Lazy Loading.
 *
 * @ flatfull.com All Rights Reserved.
 * Author url: http://themeforest.net/user/flatfull
 */
 angular.module('ui.load', [])
	.service('uiLoad', ['$document', '$q', '$timeout', function ($document, $q, $timeout) {

		var loaded = [];
		var promise = false;
		var deferred = $q.defer();

		/**
		 * Chain loads the given sources
		 * @param srcs array, script or css
		 * @returns {*} Promise that will be resolved once the sources has been loaded.
		 */
		this.load = function (srcs) {
			srcs = angular.isArray(srcs) ? srcs : srcs.split(/\s+/);
			var self = this;
			if(!promise){
				promise = deferred.promise;
			}
      angular.forEach(srcs, function(src) {
      	promise = promise.then( function(){
      		return src.indexOf('.css') >=0 ? self.loadCSS(src) : self.loadScript(src);
      	} );
      });
      deferred.resolve();
      return promise;
		}

		/**
		 * Dynamically loads the given script
		 * @param src The url of the script to load dynamically
		 * @returns {*} Promise that will be resolved once the script has been loaded.
		 */
		this.loadScript = function (src) {
			if(loaded[src]) return loaded[src].promise;

			var deferred = $q.defer();
			var script = $document[0].createElement('script');
			script.src = src;
			script.onload = function (e) {
				$timeout(function () {
					deferred.resolve(e);
				});
			};
			script.onerror = function (e) {
				$timeout(function () {
					deferred.reject(e);
				});
			};
			$document[0].body.appendChild(script);
			loaded[src] = deferred;

			return deferred.promise;
		};

		/**
		 * Dynamically loads the given CSS file
		 * @param href The url of the CSS to load dynamically
		 * @returns {*} Promise that will be resolved once the CSS file has been loaded.
		 */
		this.loadCSS = function (href) {
			if(loaded[href]) return loaded[href].promise;

			var deferred = $q.defer();
			var style = $document[0].createElement('link');
			style.rel = 'stylesheet';
			style.type = 'text/css';
			style.href = href;
			style.onload = function (e) {
				$timeout(function () {
					deferred.resolve(e);
				});
			};
			style.onerror = function (e) {
				$timeout(function () {
					deferred.reject(e);
				});
			};
			$document[0].head.appendChild(style);
			loaded[href] = deferred;

			return deferred.promise;
		};
}]);

angular.module('app.varService', [])
    .factory('VarService', function () {
        var savedData = {};
         function set(id, data) {
           savedData[id] = data;
         }
         function get(i) {
          return savedData[i];
         }
         function getAll() {
          return savedData;
         }
         function clear() {
             return savedData = {};
         }

         return {
              set: set,
              get: get,
              all: getAll,
              clearAll: clear
         }

    });

angular.module('CheckUser',[])
.directive('checkUser', ['$rootScope', '$location', 'userSrv',
  function ($r, $location, userSrv) {
    return {
      link: function (scope, elem, attrs, ctrl) {
        $r.$on('$routeChangeStart', function(e, curr, prev){
          if (!prev.access.isFree && !userSrv.isLogged) {
            // reload the login route
          }
          /*
          * IMPORTANT:
          * It's not difficult to fool the previous control,
          * so it's really IMPORTANT to repeat server side
          * the same control before sending back reserved data.
          */
        });
      }
    }
  }]);

angular.module('app.directives', ['CheckUser', 'ui.jq', 'ngFacebook']);//,'angularPayments']);

/**
 * Angular Facebook service
 * ---------------------------
 *
 * Authored by  AlmogBaku (GoDisco)
 *              almog@GoDisco.net
 *              http://www.GoDisco.net/
 *
 * 9/8/13 10:25 PM
 */

angular.module('ngFacebook', [])
  .provider('$facebook', function() {
    var config = {
      permissions:    'email',
      appId:          null,
      version:        'v2.0',
      display:        'iframe',
      customInit:     {}
    };

    this.setAppId = function(appId) {
      config.appId=appId;
      return this;
    };
    this.getAppId = function() {
      return config.appId;
    };
    this.setVersion = function(version) {
      config.version=version;
      return this;
    };
    this.getVersion = function() {
      return config.version;
    };
    this.setPermissions = function(permissions) {
      if(permissions instanceof Array) {
        permissions.join(',');
      }
      config.permissions=permissions;
      return this;
    };
    this.getPermissions = function() {
      return config.permissions;
    };
    this.setCustomInit = function(customInit) {
      if(angular.isDefined(customInit.appId)) {
        this.setAppId(customInit.appId);
      }
      config.customInit=customInit;
      return this;
    };
    this.getCustomInit = function() {
      return config.customInit;
    };

    this.$get = ['$q', '$rootScope', '$window', function($q, $rootScope, $window) {
      var $facebook=$q.defer();
      $facebook.config = function(property) {
        return config[property];
      };

      //Initialization
      $facebook.init = function() {
        if($facebook.config('appId')==null)
          throw "$facebookProvider: `appId` cannot be null";

        $window.FB.init(
          angular.extend({ appId: $facebook.config('appId'), version: $facebook.config('version') }, $facebook.config("customInit"))
        );
        $rootScope.$broadcast("fb.load", $window.FB);
      };

      $rootScope.$on("fb.load", function(e, FB) {
        $facebook.resolve(FB);

        //Define action events
        angular.forEach([
          'auth.login', 'auth.logout', 'auth.prompt',
          'auth.sessionChange', 'auth.statusChange', 'auth.authResponseChange',
          'xfbml.render', 'edge.create', 'edge.remove', 'comment.create',
          'comment.remove', 'message.send'
        ],function(event) {
          FB.Event.subscribe(event, function(response) {
            $rootScope.$broadcast("fb."+event, response, FB);
            if(!$rootScope.$$phase) $rootScope.$apply();
          });
        });

        // Make sure 'fb.auth.authResponseChange' fires even if the user is not logged in.
        $facebook.getLoginStatus();
        $facebook.canvasSetAutoResize();
      });

      /**
       * Internal cache
       */
      $facebook._cache={};
      $facebook.setCache = function(attr,val) {
        $facebook._cache[attr]=val;
      };
      $facebook.getCache = function(attr) {
        if(angular.isUndefined($facebook._cache[attr])) return false;
        return $facebook._cache[attr];
      };
      $facebook.clearCache = function() {
        $facebook._cache = {};
      };

      /**
       * Authentication
       */

      var firstAuthResp=$q.defer();
      var firstAuthRespReceived=false;
      function resolveFirstAuthResp(FB) {
        if (!firstAuthRespReceived) {
          firstAuthRespReceived=true;
          firstAuthResp.resolve(FB);
        }
      }

      $facebook.setCache("connected", null);
      $facebook.isConnected = function() {
        return $facebook.getCache("connected");
      };
      $rootScope.$on("fb.auth.authResponseChange", function(event, response, FB) {
        $facebook.clearCache();

        if(response.status=="connected") {
          $facebook.setCache("connected", true);
        } else {
          $facebook.setCache("connected", false);
        }
        resolveFirstAuthResp(FB);
      });

      $facebook.getAuthResponse = function () {
        return FB.getAuthResponse();
      };
      $facebook.getLoginStatus = function (force) {
        var deferred=$q.defer();

        return $facebook.promise.then(function(FB) {
          FB.getLoginStatus(function(response) {
            if(response.error)  deferred.reject(response.error);
            else {
                deferred.resolve(response);
                if($facebook.isConnected()==null)
                    $rootScope.$broadcast("fb.auth.authResponseChange", response, FB);
            }
            if(!$rootScope.$$phase) $rootScope.$apply();
          }, force);
          return deferred.promise;
        });
      };
      $facebook.login = function (permissions, rerequest) {
        if(permissions==undefined) permissions=$facebook.config("permissions");
        var deferred=$q.defer();

        var loginOptions = { scope: permissions };
        if (rerequest) {
          loginOptions.auth_type = 'rerequest';
        }

        return $facebook.promise.then(function(FB) {
          FB.login(function(response) {
            if(response.error)  deferred.reject(response.error);
            else                deferred.resolve(response);
            if(!$rootScope.$$phase) $rootScope.$apply();
          }, loginOptions);
          return deferred.promise;
        });
      };
      $facebook.logout = function () {
        var deferred=$q.defer();

        return $facebook.promise.then(function(FB) {
          FB.logout(function(response) {
            if(response.error)  deferred.reject(response.error);
            else                deferred.resolve(response);
            if(!$rootScope.$$phase) $rootScope.$apply();
          });
          return deferred.promise;
        });
      };
      $facebook.ui = function (params) {
        var deferred=$q.defer();

        return $facebook.promise.then(function(FB) {
          FB.ui(params, function(response) {
            if(response && response.error_code) {
              deferred.reject(response.error_message);
            } else {
              deferred.resolve(response);
            }
            if(!$rootScope.$$phase) $rootScope.$apply();
          });
          return deferred.promise;
        });
      };
      $facebook.api = function () {
        var deferred=$q.defer();
        var args=arguments;
        args[args.length++] = function(response) {
          if(response.error)        deferred.reject(response.error);
          if(response.error_msg)    deferred.reject(response);
          else                      deferred.resolve(response);
          if(!$rootScope.$$phase) $rootScope.$apply();
        };

        return firstAuthResp.promise.then(function(FB) {
          FB.api.apply(FB, args);
          return deferred.promise;
        });
      };

      /**
       * API cached request - cached request api with promise
       *
       * @param path
       * @returns $q.defer.promise
       */
      $facebook.cachedApi = function() {
        if(typeof arguments[0] !== 'string')
          throw "$facebook.cacheApi can works only with graph requests!";

        var promise = $facebook.getCache(arguments[0]);
        if(promise) return promise;

        var result = $facebook.api.apply($facebook, arguments);
        $facebook.setCache(arguments[0], result);

        return result;
      };

      $facebook.canvasSetAutoGrow = function () {
        return FB.Canvas.setAutoGrow();
      };

      $facebook.canvasScrollTop = function (x,y) {
        return FB.Canvas.scrollTo(x,y);
      };

      $facebook.canvasSetAutoResize = function () {
        setInterval(function() {
          if (!FB)
            return;
          var height = angular.element(document.querySelector('body'))[0].offsetHeight;
          return FB.Canvas.setSize({ height: height });
        }, 500);
      };

      return $facebook;
    }];
  })
  .run(['$rootScope', '$window', '$facebook', function($rootScope, $window, $facebook) {
    $window.fbAsyncInit = function() {
      $facebook.init();
      if(!$rootScope.$$phase) $rootScope.$apply();
    };
  }]);

'use strict';

/**
 * 0.1.1
 * General-purpose jQuery wrapper. Simply pass the plugin name as the expression.
 *
 * It is possible to specify a default set of parameters for each jQuery plugin.
 * Under the jq key, namespace each plugin by that which will be passed to ui-jq.
 * Unfortunately, at this time you can only pre-define the first parameter.
 * @example { jq : { datepicker : { showOn:'click' } } }
 *
 * @param ui-jq {string} The $elm.[pluginName]() to call.
 * @param [ui-options] {mixed} Expression to be evaluated and passed as options to the function
 *     Multiple parameters can be separated by commas
 * @param [ui-refresh] {expression} Watch expression and refire plugin on changes
 *
 * @example <input ui-jq="datepicker" ui-options="{showOn:'click'},secondParameter,thirdParameter" ui-refresh="iChange">
 */
angular.module('ui.jq', ['ui.load']).
  value('uiJqConfig', {}).
  directive('uiJq', ['uiJqConfig', 'JQ_CONFIG', 'uiLoad', '$timeout', function uiJqInjectingFunction(uiJqConfig, JQ_CONFIG, uiLoad, $timeout) {

  return {
    restrict: 'A',
    compile: function uiJqCompilingFunction(tElm, tAttrs) {

      if (!angular.isFunction(tElm[tAttrs.uiJq]) && !JQ_CONFIG[tAttrs.uiJq]) {
        throw new Error('ui-jq: The "' + tAttrs.uiJq + '" function does not exist');
      }
      var options = uiJqConfig && uiJqConfig[tAttrs.uiJq];

      return function uiJqLinkingFunction(scope, elm, attrs) {

        function getOptions(){
          var linkOptions = [];

          // If ui-options are passed, merge (or override) them onto global defaults and pass to the jQuery method
          if (attrs.uiOptions) {
            linkOptions = scope.$eval('[' + attrs.uiOptions + ']');
            if (angular.isObject(options) && angular.isObject(linkOptions[0])) {
              linkOptions[0] = angular.extend({}, options, linkOptions[0]);
            }
          } else if (options) {
            linkOptions = [options];
          }
          return linkOptions;
        }

        // If change compatibility is enabled, the form input's "change" event will trigger an "input" event
        if (attrs.ngModel && elm.is('select,input,textarea')) {
          elm.bind('change', function() {
            elm.trigger('input');
          });
        }

        // Call jQuery method and pass relevant options
        function callPlugin() {
          $timeout(function() {
            elm[attrs.uiJq].apply(elm, getOptions());
          }, 0, false);
        }

        function refresh(){
          // If ui-refresh is used, re-fire the the method upon every change
          if (attrs.uiRefresh) {
            scope.$watch(attrs.uiRefresh, function() {
              callPlugin();
            });
          }
        }

        if ( JQ_CONFIG[attrs.uiJq] ) {
          uiLoad.load(JQ_CONFIG[attrs.uiJq]).then(function() {
            callPlugin();
            refresh();
          }).catch(function() {
            
          });
        } else {
          callPlugin();
          refresh();
        }
      };
    }
  };
}]);
angular.module('app.modules', ['app.landing', 'app.access', 'app.category', 'app.product']);

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

var settings = {
    baseApiUrl: 'http://localhost:1337'
}

angular.module('app', ['ui.router', 'ui.bootstrap','restangular', 'app.directives', 'app.filters', 'app.services', 'app.modules'])

.config(['$stateProvider', '$urlRouterProvider', 'RestangularProvider', function($stateProvider, $urlRouterProvider, RestangularProvider){
    RestangularProvider.addResponseInterceptor(function(data, operation, what, url, response, deferred) {
        if (data.response && data.response.data) {
            var returnedData = data.response.data;
            return returnedData;
        } else {
            return data;
        };
    });
    $urlRouterProvider.otherwise('/');
}])
.run(['$rootScope', '$state', '$stateParams', 'Auth', '$location',
    function ($rootScope, $state, $stateParams, Auth, $location) {
        $rootScope.$state = $state;
        $rootScope.$stateParams = $stateParams;
        $rootScope.$on('$stateChangeStart', function(event, toState, toParams, fromState, fromParams) {
            var user = Auth.getUser();
            if (user) {
                if (Date.create(user.exp * 1000).isPast()) {
                    event.preventDefault();

                    Auth.logout();
                    $state.go('access.login');
                }
            }

            if (toState.name == 'access.login' && Auth.isAuthenticated()) {
                $location.path('/');
            }

            if (!Auth.authorize(toState.role)) {
                event.preventDefault();

                $state.go('access.login');
            }

        });

    }

])

//API restangular
.factory('API', ['Restangular', function(Restangular) {
    return Restangular.withConfig(function(RestangularConfigurer) {
        RestangularConfigurer.setBaseUrl(settings.baseApiUrl);
    });
}])

.controller('AppCtrl', ['$scope', '$window', '$state', 'Auth', '$rootScope',
    function ($scope, $window, $state, Auth, $rootScope) {
        // config
        $scope.app = {
            name: 'Abuntoo',
            version: '0.0.1'
        }

        $rootScope.user = Auth.getUser();
        $scope.$on('fetchUserData', function (event, data) {
            $rootScope.user = Auth.getUser();
        });
        $scope.logout = function () {
            Auth.logout();
            window.location.reload();
            // $state.go('landing');
        }
        $scope.search = {};
        $scope.searchSite = function(){
            if($scope.search.text){
                $state.go('reward.searchsite', {search_query: $scope.search.text});
            }
        }

    }
])
.filter("sanitize", ['$sce', function($sce) {
  return function(htmlCode){
    return $sce.trustAsHtml(htmlCode);
  }
}]);
