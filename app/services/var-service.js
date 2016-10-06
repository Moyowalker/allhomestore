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
