

      <!-- End Content -->
      </div>
    </td>
  </tr>
  <tr>
    <td colspan="10">
      <div id="footer">
      <table width="100%">
        <tr> 
          <td width="10%" align="left">
            <a href="javascript:popUp('<?=$current_top?>/help.html#<?=$current_sub?>', '500', '400')"><img src='images/help.png' alt='Help!' title='Help!'></a>
          </td>
          <td width="80%" align="center"><?if(isset($my_table)) $my_table->print_pager()?></td>
          <td width="10%" nowrap align="right">
          <?php if(isset($my_table) && count($my_table->rows)){
  	       $_SESSION['table']=serialize($my_table);
               #if( ($current_top=="node" && $current_sub=="view") || ($current_top=="violation" && $current_sub=="view") || ($current_top=="report"))
	       #  print "<a href=scan/nessus.php?import=true><img border=0 src='images/nessus.gif'></a> ";
	       if(($current_top == 'class' && $current_sub == 'fingerprint') || ($current_top== 'status' && $current_sub == 'reports' && $_GET['type'] == 'unknownprints')){
	  	 print "<a href='$current_top/$current_sub.php?menu=$_GET[menu]&amp;type=$_GET[type]&amp;upload=true'><img src='images/up.png' alt='Share Unknown Fingerprints' title='Share Unknown Fingerprints'></a> ";
	  	 print "<a href='$current_top/$current_sub.php?menu=$_GET[menu]&amp;type=$_GET[type]&amp;update=true'><img src='images/update.png' alt='Update Fingerprints &amp; OUI Prefixes' title='Update Fingerprints &amp; OUI Prefixes'></a> ";
	       }
               print "<a href=\"javascript:popUp('/exporter.php', '175', '1200')\"><img border=0 src='images/csv.png' alt='Download CSV of this data' title='Download CSV of this data'></a>";
            }
	    if(isset($is_printable) && $is_printable){
               print "<a href='/printer.php?current_top=$current_top&amp;current_sub=$current_sub&amp;img_src=".urlencode($img_src)."' target=_NEW><img border=0 src='images/printer.png' alt='View a Printer Friendly Version' title='View a Printer Friendly Version'></a>";
	    }
          ?>      
          </td>
        </tr>
      </table>
      </div>
    </td>
  </tr>
  <tr>
<!--    <td align="right" colspan="2"><font size="1"><?=meta("pf-version")?></font></td> -->
    <td align="right" colspan="2"><font size="1"><?=meta("pf-version")?></font></td>
  </tr>
</table>
</div>

</body>
</html>
