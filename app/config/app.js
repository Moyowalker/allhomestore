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
