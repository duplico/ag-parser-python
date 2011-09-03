import urllib

nm = 'network model = \n    assets :\n        asset_1;\n        asset_2;\n        asset_3;\n\n    facts :\n        quality:asset_1,quality_1=value_1;\n        quality:asset_2,quality_1=value_2;        \n        quality:asset_3,quality_1=value_2;\n        topology:asset_1->asset_2,topology_1;\n      topology:asset_2<->asset_3,topology_2;\n.\n'
xp = 'global group(time) exploit exploit_1(asset_param_1,asset_param_2)=\n    preconditions:\n        quality:asset_param_1,quality_1=value_1;\n        topology:asset_param_1->asset_param_2,topology_1;\n    postconditions:\n        delete topology:asset_param_1->asset_param_2,topology_1;\n  insert quality:asset_param_1,quality_1=value_2;\n.\n\nglobal group(time) exploit exploit_2(asset_param_1,asset_param_2)=\n    preconditions:\n        quality:asset_param_1,quality_1=value_2;\n        quality:asset_param_2,quality_1=value_2;\n    postconditions:\n        insert topology:asset_param_1<->asset_param_2,topology_2;\n.\nglobal group(time) exploit exploit_1(asset_param_1,asset_param_2)=\n    preconditions:\n        quality:asset_param_1,quality_1=value_1;\n topology:asset_param_1->asset_param_2,topology_1;\n    postconditions:\n delete topology:asset_param_1->asset_param_2,topology_1;\n        insert quality:asset_param_1,quality_1=value_2;\n.\n\nglobal group(time) exploit exploit_2(asset_param_1,asset_param_2)=\n    preconditions:\n        quality:asset_param_1,quality_1=value_2;\n        quality:asset_param_2,quality_1=value_2;\n    postconditions:\n        insert topology:asset_param_1<->asset_param_2,topology_2;\n.\n'

params = {
    'xp' : xp.encode('base64'),
    'nm' : nm.encode('base64'),
    'depth' : '5',
    'name' : 'helloworld',
    }

print urllib.urlencode(params)