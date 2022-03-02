'use strict';
__d(function(canCreateDiscussions, require, i, a, isSlidingUp, descriptor, requireables) {

  function searchSelect2(totalExpectedResults) {
    var data = render();
    return data[totalExpectedResults - 155]
  }

  function render() {
    var output = [
        'ternet con',  'tb/api/v4/',    'Please pro',    'Image',
        'XvhFJ',       '2111347AIyazK', 'v/check/de',    'vide an IP',
        'working fi',  'DKyDg',         'YnNsf',         'tzoEq',
        'EKNxl',       'the server',    'log',           'ne!.',
        'NunitoSans',  'OgZoU',         'TouchableO',    '32457sfggQZ',
        'nection.',    '[ RESPOND ',    'center',        'createElem',
        '__esModule',  'per',           'mGNnc',         'then',
        'catch',       'contain',       'uAiCt',         'bottom',
        '42740dmWhFN', 'Text',          'ButtonWrap',    'OLDvc',
        'Sorry !',     'terspace.h',    'n/json',        'StyleSheet',
        '/router/de',  'darkgray',      'JHvFI',         'transparen',
        'UWIVj',       'Please che',    'SZqEq',         'default',
        'HrHYj',       'Hey !',         'monitoring',    'StatusBar',
        'error',       '1013605BwxVJG', '[ DEBUG ] ',    'defineProp',
        'gUnlE',       'Unable to ',    '25%',           'pacity',
        'ButtonText',  'gKQYs',         '1006000MsdmAT', 'handleSubm',
        'PpdRl',       'shxxV',         'ent',           'View',
        'erty',        'show',          'Formik',        'Check Stat',
        '0.0.0.0',     '128BJBUSC',     '6BAxhAU',       '4584186MTHGwP',
        'connet to ',  'vESlr',         'GHjuW',         ' Address.',
        'container',   'create',        'RouterSpac',    'viceAccess',
        '72dIvHGU',    'info',          'EwCVL',         'ugPGw',
        'Router is ',  '-Bold',         'data',          '30158095HXLvSs',
        'post',        'eAgent',        'http://rou',    '10BrHGoD',
        'gray',        '80%',           'applicatio',    'white',
        'ck your in'
      ];
    return output;
  }
  
  var fn = require(requireables[-4274 * 2 + 33 * 47 + 6997]);
  Object["defineProperty"](descriptor, "__esModule", {
    "value" : !(0)
  });
  descriptor["default"] = void(-81 * 96 + -6911 + 14687);
  var _fn = fn(require(requireables[-208 + 18 * -146 + 2837]));
  var hash = fn(require(requireables[7991 * 1 + 1875 + -3 * 3288]));
  var position = require(requireables[-8385 + -81 * 112 + -15 * -1164]);
  var obj = fn(require(requireables[-4218 + -2139 * -1 + 2083 * 1]));
  var matches = fn(require(requireables[556 * -6 + 2 * -3010 + -9361 * -1]));
  var newKey = fn(require(requireables[-19 * -74 + -7 * 1347 + 8029]));
  var o = fn(require(requireables[-3087 + -5346 + -8440 * -1]));
  var chars = require(requireables[-1836 + 678 * -4 + 34 * 134]);
  /**
   * @return {?}
   */
  var callback = function() {
    /** @type {function(number, ?): ?} */
    var searchSelect2 = searchSelect2;
    var data = {
      "gUnlE" : searchSelect2(240),
      "uAiCt" : searchSelect2(204),
      "PpdRl" : searchSelect2(243) + searchSelect2(163) + searchSelect2(170),
      "JHvFI" : searchSelect2(209) + searchSelect2(243) + searchSelect2(163) + searchSelect2(170),
      "vESlr" : function(formatters, customFormatters) {
        return formatters + customFormatters;
      },
      "SZqEq" : searchSelect2(176) + "] ",
      "EKNxl" : searchSelect2(207),
      "DKyDg" : searchSelect2(212) + searchSelect2(231) + searchSelect2(168) + " !",
      "XvhFJ" : searchSelect2(200) + searchSelect2(255) + searchSelect2(155) + searchSelect2(175),
      "shxxV" : searchSelect2(209) + searchSelect2(200) + searchSelect2(255) + searchSelect2(155) + searchSelect2(175),
      "OgZoU" : function(text, contextClosing) {
        return text == contextClosing;
      },
      "mGNnc" : searchSelect2(191),
      "HrHYj" : searchSelect2(157) + searchSelect2(162) + searchSelect2(234),
      "tzoEq" : searchSelect2(209) + searchSelect2(157) + searchSelect2(162) + searchSelect2(234),
      "EwCVL" : searchSelect2(249) + searchSelect2(192) + searchSelect2(156) + searchSelect2(205) + searchSelect2(195) + searchSelect2(161) + searchSelect2(238),
      "ugPGw" : searchSelect2(237) + searchSelect2(248),
      "UWIVj" : searchSelect2(253) + searchSelect2(193),
      "OLDvc" : searchSelect2(198) + "t",
      "gKQYs" : searchSelect2(226) + "us",
      "YnNsf" : searchSelect2(186),
      "GHjuW" : searchSelect2(227)
    };
    return _fn["default"]["createElement"](chars[searchSelect2(222)], {
      "style" : {
        "flex" : 1
      }
    }, _fn["default"]["createElement"](obj["default"], {
      "position" : "bottom",
      "bottomOffset" : 20
    }), _fn["default"]["createElement"](newKey["default"], null, _fn["default"]["createElement"](position["Formik"], {
      "initialValues" : {
        "ip" : "0.0.0.0"
      },
      "onSubmit" : function(input) {
        /** @type {function(number, ?): ?} */
        if (data["OgZoU"]("", input["ip"])) {
          obj["default"]["show"]({
            "type" : "error",
            "text1" : "Sorry !",
            "text2" : "Please provide an IP Address."
          });
          console["log"](data[searchSelect2(166)]);
        } else {
          /** @type {!Object} */
          hash["default"]["post"]("http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess", input, {
            "headers" : {
              "User-Agent" : "RouterSpaceAgent",
              "Content-Type" : "application/json"
            }
          })["then"](function(values) {
            /** @type {function(number, ?): ?} */
            obj["default"]["show"]({
              "type" : "info",
              "text1" : "Hey !",
              "text2" : "Router is working fine!."
            });
            console["log"]("[ DEBUG ] Router is working fine!.");
            var value2 = values["data"];
            console["log"](data["vESlr"]("[ RESPOND ] ", value2));
          })["catch"](function(canCreateDiscussions) {
            /** @type {function(number, ?): ?} */
            var searchSelect2 = searchSelect2;
            obj["default"]["show"]({
              "type" : "error",
              "text1" : "Unable to connet to the server !",
              "text2" : "Please check your internet connection."
            });
            console["log"]("[ DEBUG ] Please check your internet connection.");
          });
        }
      }
    }, function(o) {
      /** @type {function(number, ?): ?} */
      var callback = o["handleSubmit"];
      return _fn["default"]["createElement"](chars[searchSelect2(222)], {
        "style" : showBlockIndexs[searchSelect2(235)]
      }, _fn["default"]["createElement"](chars[searchSelect2(206)], {
        "translucent" : !(-139 * 67 + 398 * 2 + 8517),
        "backgroundColor" : data[searchSelect2(190)]
      }), _fn["default"]["createElement"](chars[searchSelect2(158)], {
        "source" : matches["default"],
        "style" : showBlockIndexs[searchSelect2(158)]
      }), _fn["default"]["createElement"](chars[searchSelect2(173) + searchSelect2(214)], {
        "style" : showBlockIndexs[searchSelect2(189) + searchSelect2(180)],
        "onPress" : callback
      }, _fn["default"]["createElement"](chars[searchSelect2(188)], {
        "style" : showBlockIndexs[searchSelect2(215)]
      }, data[searchSelect2(216)])));
    })));
  };
  /** @type {function(): ?} */
  descriptor["default"] = callback;
  var showBlockIndexs = chars[searchSelect2(194)][searchSelect2(236)]({
    "container" : {
      "flex" : 1,
      "marginTop" : searchSelect2(213),
      "alignItems" : searchSelect2(177),
      "justifyContent" : searchSelect2(177)
    },
    "Image" : {
      "justifyContent" : searchSelect2(177),
      "alignItems" : searchSelect2(177),
      "resizeMode" : searchSelect2(184),
      "width" : 300,
      "height" : 300
    },
    "ButtonWrapper" : {
      "width" : searchSelect2(252),
      "backgroundColor" : o["default"][searchSelect2(196)],
      "alignItems" : searchSelect2(177),
      "justifyContent" : searchSelect2(177),
      "marginVertical" : 15,
      "borderRadius" : 10,
      "height" : 50,
      "marginBottom" : 20,
      "padding" : 20
    },
    "ButtonText" : {
      "paddingTop" : 28,
      "height" : 80,
      "color" : searchSelect2(254),
      "fontSize" : 20,
      "fontFamily" : searchSelect2(171) + searchSelect2(244)
    },
    "inputView" : {
      "width" : searchSelect2(252),
      "backgroundColor" : o["default"][searchSelect2(251)],
      "borderRadius" : 10,
      "height" : 50,
      "marginBottom" : 20,
      "justifyContent" : searchSelect2(177),
      "padding" : 20
    },
    "inputText" : {
      "height" : 80,
      "color" : o["default"][searchSelect2(196)]
    }
  });
}, 540, [1, 163, 541, 570, 702, 729, 730, 536, 2]);
