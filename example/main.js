debugger;

import goognehome from 'google-home-notifier';

goognehome.device('ファミリー ルーム', 'ja').notify({text: 'こんにちは'}).catch(trace);