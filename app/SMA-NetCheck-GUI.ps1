<#
.SYNOPSIS
    SMA NetCheck - interfejs graficzny (WPF), PL / EN / DE.
    Wymaga plików SMA-NetCheck.ps1 i SMA-NetCheck.lang.ps1 w tym samym folderze.
    Uruchamianie: Start-SMA-NetCheck.cmd w folderze nadrzędnym (bez okna konsoli).
#>
$ErrorActionPreference = 'Stop'
$libPath = Join-Path $PSScriptRoot 'SMA-NetCheck.ps1'

try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    if (-not (Test-Path $libPath)) { throw "SMA-NetCheck.ps1 not found in $PSScriptRoot" }
    . $libPath     # funkcje testów, T(), Save-Report (w tym wątku: lista kart, raport, tłumaczenia)

    if (-not ('SmaNetCheck.ResultItem' -as [type])) {
        Add-Type -TypeDefinition @'
namespace SmaNetCheck {
    public class ResultItem {
        public string Time { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public string Status { get; set; }
        public string StatusText { get; set; }
        public string Detail { get; set; }
        public string Hint { get; set; }
        public bool HasHint { get { return !string.IsNullOrEmpty(Hint); } }
    }
}
'@
    }

    # =================================================================================
    #  XAML  (Tag="L:klucz" = tekst ze słownika językowego)
    # =================================================================================
    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SMA NetCheck" Width="1280" Height="820" MinWidth="1020" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="#F3F5F8"
        FontFamily="Segoe UI" FontSize="13" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <BooleanToVisibilityConverter x:Key="B2V"/>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="White"/>
      <Setter Property="CornerRadius" Value="8"/>
      <Setter Property="BorderBrush" Value="#E1E5EA"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16"/>
    </Style>

    <Style x:Key="SectionTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Foreground" Value="#7A8694"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
    </Style>

    <Style x:Key="PrimaryButton" TargetType="Button">
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Background" Value="#0B5FA5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.85"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.7"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.35"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="GhostButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
      <Setter Property="Background" Value="#E8F0F8"/>
      <Setter Property="Foreground" Value="#0B5FA5"/>
    </Style>
    <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
      <Setter Property="Background" Value="#C62828"/>
    </Style>
    <!-- Przyciski-linki w nagłówku: przezroczyste, podświetlane po najechaniu -->
    <Style x:Key="HeaderLink" TargetType="Button">
      <Setter Property="Foreground" Value="#D6E4F5"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Padding" Value="10,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#1C4B85"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#245A9E"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="0,5"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="BorderBrush" Value="#CBD2DA"/>
    </Style>

    <Style x:Key="TileNumber" TargetType="TextBlock">
      <Setter Property="FontSize" Value="28"/>
      <Setter Property="FontWeight" Value="Bold"/>
    </Style>
    <Style x:Key="TileLabel" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Foreground" Value="#6B7785"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <!-- ===== Nagłówek ===== -->
    <Border DockPanel.Dock="Top" Background="#0B2E59" Padding="20,12">
      <Grid>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <StackPanel VerticalAlignment="Center">
            <TextBlock Text="SMA NetCheck" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
            <TextBlock x:Name="SubTitle" Foreground="#A9C1DD" FontSize="12"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
          <!-- Linki: status serwerów, informacje o programie -->
          <Button x:Name="BtnStatus" Tag="L:gui.statusPage" Style="{StaticResource HeaderLink}"/>
          <Button x:Name="BtnAbout" Tag="L:gui.about" Style="{StaticResource HeaderLink}" Margin="4,0,0,0"/>
          <Border Width="1" Height="26" Background="#2E4E7A" Margin="14,0" VerticalAlignment="Center"/>
          <!-- Ustawienia: język, uprawnienia -->
          <TextBlock Text="&#x1F310;" FontFamily="Segoe UI Emoji" FontSize="15" Foreground="#A9C1DD" VerticalAlignment="Center" Margin="0,0,6,0"/>
          <ComboBox x:Name="CmbLang" Width="120" Height="28" VerticalContentAlignment="Center" Margin="0,0,14,0"/>
          <Border x:Name="AdminBadge" CornerRadius="11" Padding="12,4" Background="#2E7D32" VerticalAlignment="Center">
            <TextBlock x:Name="AdminText" Foreground="White" FontSize="11" FontWeight="SemiBold"/>
          </Border>
          <Button x:Name="BtnElevate" Tag="L:gui.elevate" Style="{StaticResource GhostButton}" Padding="12,6"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- ===== Pasek stanu ===== -->
    <Border DockPanel.Dock="Bottom" Background="White" BorderBrush="#E1E5EA" BorderThickness="0,1,0,0" Padding="16,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="280"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="StatusText" Tag="L:gui.ready" VerticalAlignment="Center" Foreground="#4A5563" TextTrimming="CharacterEllipsis"/>
        <ProgressBar x:Name="Progress" Grid.Column="1" Height="8" Minimum="0" Maximum="100" Visibility="Hidden" Foreground="#0B5FA5" Background="#E8EDF2" BorderThickness="0"/>
      </Grid>
    </Border>

    <!-- ===== Główna część ===== -->
    <Grid Margin="16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="350"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Lewy panel: przewijane ustawienia + przyciski zawsze widoczne na dole -->
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Tag="L:gui.adapterTitle" Style="{StaticResource SectionTitle}"/>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <ComboBox x:Name="CmbAdapter" Height="30" VerticalContentAlignment="Center"/>
                <Button x:Name="BtnRefresh" Grid.Column="1" Content="&#x21BB;" Width="34" Height="30" Margin="6,0,0,0" Padding="0" FontSize="15" Style="{StaticResource GhostButton}"/>
              </Grid>
              <TextBlock x:Name="AdapterInfo" Margin="0,10,0,0" TextWrapping="Wrap" Foreground="#4A5563" FontSize="12" LineHeight="18"/>
              <WrapPanel x:Name="AdapterFlags" Margin="0,6,0,0"/>
            </StackPanel>
          </Border>

          <Border Style="{StaticResource Card}" Margin="0,12,0,0">
            <StackPanel>
              <TextBlock Tag="L:gui.tests" Style="{StaticResource SectionTitle}"/>
              <CheckBox x:Name="ChkPortal" IsChecked="True">
                <StackPanel Margin="4,-2,0,0">
                  <TextBlock Tag="L:gui.portal" FontWeight="SemiBold"/>
                  <TextBlock Tag="L:gui.portal.d" FontSize="11" Foreground="#0B5FA5" TextWrapping="Wrap"/>
                </StackPanel>
              </CheckBox>
              <CheckBox x:Name="ChkScan" IsChecked="True">
                <StackPanel Margin="4,-2,0,0">
                  <TextBlock Tag="L:gui.scan" FontWeight="SemiBold"/>
                  <TextBlock Tag="L:gui.scan.d" FontSize="11" Foreground="#0B5FA5" TextWrapping="Wrap"/>
                </StackPanel>
              </CheckBox>
              <StackPanel Margin="22,0,0,6">
                <CheckBox x:Name="ChkRange" Margin="0,2">
                  <TextBlock Tag="L:gui.range" Margin="4,-1,0,0" FontSize="12" Foreground="#4A5563"/>
                </CheckBox>
                <TextBox x:Name="TxtRange" Margin="0,2,0,0" FontFamily="Consolas" IsEnabled="False"/>
                <TextBlock Tag="L:gui.range.hint" FontSize="11" Foreground="#0B5FA5" TextWrapping="Wrap" Margin="0,2,0,0"/>
              </StackPanel>
              <CheckBox x:Name="ChkMulticast" IsChecked="True">
                <StackPanel Margin="4,-2,0,0">
                  <TextBlock Tag="L:gui.mc" FontWeight="SemiBold"/>
                  <TextBlock Tag="L:gui.mc.d" FontSize="11" Foreground="#0B5FA5" TextWrapping="Wrap"/>
                </StackPanel>
              </CheckBox>
              <StackPanel Orientation="Horizontal" Margin="22,2,0,6">
                <TextBlock Tag="L:gui.listen" VerticalAlignment="Center" Foreground="#4A5563" FontSize="12"/>
                <ComboBox x:Name="CmbSeconds" Width="190" Margin="8,0,0,0"/>
              </StackPanel>
              <CheckBox x:Name="ChkDevices">
                <StackPanel Margin="4,-2,0,0">
                  <TextBlock Tag="L:gui.devices" FontWeight="SemiBold"/>
                  <TextBlock Tag="L:gui.devices.d" FontSize="11" Foreground="#0B5FA5" TextWrapping="Wrap"/>
                </StackPanel>
              </CheckBox>
              <TextBox x:Name="TxtDevices" Margin="22,4,0,0" Height="74" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
            </StackPanel>
          </Border>

          <Border Style="{StaticResource Card}" Margin="0,12,0,0">
            <StackPanel>
              <TextBlock Tag="L:gui.options" Style="{StaticResource SectionTitle}"/>
              <CheckBox x:Name="ChkFirewall">
                <TextBlock Tag="L:gui.fwrule" Margin="4,-1,0,0" TextWrapping="Wrap"/>
              </CheckBox>
            </StackPanel>
          </Border>
        </StackPanel>
      </ScrollViewer>
        <StackPanel Grid.Row="1">
          <Button x:Name="BtnRun" Tag="L:gui.run" Style="{StaticResource PrimaryButton}" Margin="0,12,0,0" FontSize="14" Height="44"/>
          <Button x:Name="BtnStop" Tag="L:gui.stop" Style="{StaticResource DangerButton}" Margin="0,8,0,0" Height="34" IsEnabled="False"/>
        </StackPanel>
      </Grid>

      <!-- Prawy panel -->
      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="2.4*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Border x:Name="VerdictCard" Style="{StaticResource Card}">
            <StackPanel VerticalAlignment="Center">
              <TextBlock x:Name="VerdictTitle" FontSize="17" FontWeight="SemiBold" Foreground="#0B2E59"/>
              <TextBlock x:Name="VerdictText" TextWrapping="Wrap" Foreground="#4A5563" Margin="0,4,0,0" FontSize="12"/>
            </StackPanel>
          </Border>
          <Border Grid.Column="1" Style="{StaticResource Card}" Margin="12,0,0,0">
            <StackPanel><TextBlock x:Name="CntFail" Text="0" Style="{StaticResource TileNumber}" Foreground="#C62828"/><TextBlock Tag="L:gui.tile.fail" Style="{StaticResource TileLabel}"/></StackPanel>
          </Border>
          <Border Grid.Column="2" Style="{StaticResource Card}" Margin="12,0,0,0">
            <StackPanel><TextBlock x:Name="CntWarn" Text="0" Style="{StaticResource TileNumber}" Foreground="#C88700"/><TextBlock Tag="L:gui.tile.warn" Style="{StaticResource TileLabel}"/></StackPanel>
          </Border>
          <Border Grid.Column="3" Style="{StaticResource Card}" Margin="12,0,0,0">
            <StackPanel><TextBlock x:Name="CntOk" Text="0" Style="{StaticResource TileNumber}" Foreground="#2E7D32"/><TextBlock Tag="L:gui.tile.ok" Style="{StaticResource TileLabel}"/></StackPanel>
          </Border>
          <Border Grid.Column="4" Style="{StaticResource Card}" Margin="12,0,0,0">
            <StackPanel><TextBlock x:Name="CntInfo" Text="0" Style="{StaticResource TileNumber}" Foreground="#1D4F91"/><TextBlock Tag="L:gui.tile.info" Style="{StaticResource TileLabel}"/></StackPanel>
          </Border>
        </Grid>

        <DockPanel Grid.Row="1" Margin="0,14,0,10">
          <CheckBox x:Name="ChkOnlyProblems" Tag="L:gui.onlyProblems" VerticalAlignment="Center" VerticalContentAlignment="Center"/>
          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnCopy" Tag="L:gui.copy" Style="{StaticResource GhostButton}" Margin="8,0,0,0"/>
            <Button x:Name="BtnReport" Tag="L:gui.report" Style="{StaticResource GhostButton}" Margin="8,0,0,0"/>
            <Button x:Name="BtnClear" Tag="L:gui.clear" Style="{StaticResource GhostButton}" Margin="8,0,0,0"/>
          </StackPanel>
        </DockPanel>

        <Border Grid.Row="2" Style="{StaticResource Card}" Padding="0">
          <Grid>
            <ListBox x:Name="LstResults" BorderThickness="0" Background="Transparent"
                     HorizontalContentAlignment="Stretch"
                     ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                     VirtualizingPanel.IsVirtualizingWhenGrouping="True"
                     VirtualizingPanel.ScrollUnit="Pixel">
              <ListBox.ItemContainerStyle>
                <Style TargetType="ListBoxItem">
                  <Setter Property="Padding" Value="10,0"/>
                  <Setter Property="BorderBrush" Value="#F0F2F5"/>
                  <Setter Property="BorderThickness" Value="0,0,0,1"/>
                </Style>
              </ListBox.ItemContainerStyle>
              <ListBox.GroupStyle>
                <GroupStyle>
                  <GroupStyle.HeaderTemplate>
                    <DataTemplate>
                      <Border Background="#F0F4F9" Padding="14,7" BorderBrush="#E1E5EA" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal">
                          <TextBlock Text="{Binding Name}" FontWeight="Bold" Foreground="#0B2E59"/>
                          <TextBlock Text="{Binding ItemCount, StringFormat='  ({0})'}" Foreground="#7A8694"/>
                        </StackPanel>
                      </Border>
                    </DataTemplate>
                  </GroupStyle.HeaderTemplate>
                </GroupStyle>
              </ListBox.GroupStyle>
              <ListBox.ItemTemplate>
                <DataTemplate>
                  <Grid Margin="0,8">
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="80"/>
                      <ColumnDefinition Width="0.9*"/>
                      <ColumnDefinition Width="1.6*"/>
                    </Grid.ColumnDefinitions>
                    <Border x:Name="Pill" CornerRadius="10" Padding="0,2" Margin="0,0,12,0" VerticalAlignment="Top" Background="#E6F0FB">
                      <TextBlock x:Name="PillText" Text="{Binding StatusText}" HorizontalAlignment="Center" FontSize="11" FontWeight="Bold" Foreground="#1D4F91"/>
                    </Border>
                    <TextBlock Grid.Column="1" Text="{Binding Name}" TextWrapping="Wrap" FontWeight="SemiBold" Foreground="#1F2933" Margin="0,0,14,0"/>
                    <StackPanel Grid.Column="2">
                      <TextBlock Text="{Binding Detail}" TextWrapping="Wrap" Foreground="#3E4A57"/>
                      <Border Visibility="{Binding HasHint, Converter={StaticResource B2V}}" Background="#FFF8E6" BorderBrush="#F0C35A" BorderThickness="3,0,0,0" Padding="9,5" Margin="0,6,0,0" CornerRadius="0,4,4,0">
                        <TextBlock Text="{Binding Hint}" TextWrapping="Wrap" Foreground="#6B4E00" FontSize="12"/>
                      </Border>
                    </StackPanel>
                  </Grid>
                  <DataTemplate.Triggers>
                    <DataTrigger Binding="{Binding Status}" Value="OK">
                      <Setter TargetName="Pill" Property="Background" Value="#E3F6E8"/>
                      <Setter TargetName="PillText" Property="Foreground" Value="#126B2E"/>
                    </DataTrigger>
                    <DataTrigger Binding="{Binding Status}" Value="WARN">
                      <Setter TargetName="Pill" Property="Background" Value="#FFF1CC"/>
                      <Setter TargetName="PillText" Property="Foreground" Value="#8A5A00"/>
                    </DataTrigger>
                    <DataTrigger Binding="{Binding Status}" Value="FAIL">
                      <Setter TargetName="Pill" Property="Background" Value="#FDE2E1"/>
                      <Setter TargetName="PillText" Property="Foreground" Value="#9B1C1C"/>
                    </DataTrigger>
                  </DataTemplate.Triggers>
                </DataTemplate>
              </ListBox.ItemTemplate>
            </ListBox>
            <StackPanel x:Name="EmptyState" HorizontalAlignment="Center" VerticalAlignment="Center" IsHitTestVisible="False">
              <TextBlock Text="&#x1F50C;" FontSize="40" HorizontalAlignment="Center" Foreground="#B8C2CC" FontFamily="Segoe UI Emoji"/>
              <TextBlock Tag="L:gui.empty" FontSize="15" Foreground="#7A8694" HorizontalAlignment="Center" Margin="0,8,0,0"/>
              <TextBlock Tag="L:gui.empty.d" FontSize="12" Foreground="#9AA5B1" HorizontalAlignment="Center" Margin="0,4,0,0"/>
            </StackPanel>
          </Grid>
        </Border>
      </Grid>
    </Grid>
  </DockPanel>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $ui = @{}
    foreach ($n in $xaml.SelectNodes("//*[@*[local-name()='Name']]")) {
        $name = $n.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
        $ui[$name] = $window.FindName($name)
    }

    # =================================================================================
    #  STAN GUI
    # =================================================================================
    $script:items     = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $script:adapters  = @()
    $script:busy      = $false
    $script:ps        = $null
    $script:handle    = $null
    $script:runStart  = $null
    $script:stopReq   = $false
    $script:verdict   = 'none'     # none / running / done
    $script:lastStatus = @{ Key = 'gui.ready'; Args = @() }
    $script:counts    = @{ OK = 0; WARN = 0; FAIL = 0; INFO = 0 }
    $script:langNames = @{ PL = 'Polski'; EN = 'English'; DE = 'Deutsch' }

    $ui.LstResults.ItemsSource = $script:items
    $view = [Windows.Data.CollectionViewSource]::GetDefaultView($script:items)
    $view.GroupDescriptions.Add((New-Object Windows.Data.PropertyGroupDescription 'Category'))

    # Wątek w tle: osobny runspace z załadowanymi funkcjami testów
    $bgSync = [hashtable]::Synchronized(@{
        Queue    = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
        Status   = ''
        Progress = -1
    })
    $bgRs = [runspacefactory]::CreateRunspace()
    $bgRs.ApartmentState = 'STA'
    $bgRs.ThreadOptions = 'ReuseThread'
    $bgRs.Open()
    $init = [powershell]::Create()
    $init.Runspace = $bgRs
    [void]$init.AddScript({
        param($lib, $bgSyncArg)
        . $lib
        Enable-NcGuiMode $bgSyncArg
        # W tle nie ma konsoli - wyciszamy wyjście tekstowe i pytania
        function global:Write-Host { }
        function global:Write-Progress { }
        function global:Read-Host { '' }
    }).AddArgument($libPath).AddArgument($bgSync)
    [void]$init.Invoke()
    if ($init.Streams.Error.Count -gt 0) { throw "Background init error: $($init.Streams.Error[0])" }
    $init.Dispose()

    $runScript = {
        param($o)
        Set-NcLanguage $o.Lang
        $script:Results.Clear()
        $script:CheckedAdapter = @{}
        $script:AllAdapters = @(Get-AdapterList)
        $script:Adapter = $script:AllAdapters | Where-Object { $_.Index -eq $o.Index -and $_.IP -eq $o.IP } | Select-Object -First 1
        if (-not $script:Adapter) {
            Add-Result (T 'cat.adapter') (T 'gui.adapterGone.n') 'FAIL' (T 'gui.adapterGone') (T 'gui.adapterGone.h')
            return
        }
        $AddFirewallRule = $o.Firewall
        try {
            if ($o.Portal)    { Invoke-PortalTest }
            if ($o.Scan)      { Invoke-SubnetScan $o.Range }
            if ($o.Multicast) { Invoke-MulticastTest $o.Seconds }
            if ($o.Devices.Count -gt 0) { Invoke-LocalTest $o.Devices }
        } finally {
            Remove-TempFirewallRule
        }
    }

    # =================================================================================
    #  FUNKCJE GUI
    # =================================================================================
    function Set-StatusKey([string]$Key) {
        $script:lastStatus = @{ Key = $Key; Args = $args }
        $ui.StatusText.Text = if ($args.Count -gt 0) { T $Key @args } else { T $Key }
    }

    function New-Chip([string]$Text, [string]$Bg, [string]$Fg) {
        $b = New-Object Windows.Controls.Border
        $b.Background = $Bg; $b.CornerRadius = 9; $b.Padding = '8,2'; $b.Margin = '0,0,6,4'
        $t = New-Object Windows.Controls.TextBlock
        $t.Text = $Text; $t.FontSize = 11; $t.FontWeight = 'SemiBold'; $t.Foreground = $Fg
        $b.Child = $t
        return $b
    }

    function Update-Adapters {
        $script:adapters = @(Get-AdapterList)
        $script:AllAdapters = $script:adapters
        $ui.CmbAdapter.Items.Clear()
        foreach ($a in $script:adapters) { [void]$ui.CmbAdapter.Items.Add("$($a.Alias)  -  $($a.IP)/$($a.Prefix)") }
        if ($script:adapters.Count -eq 0) {
            Show-AdapterInfo
            $ui.BtnRun.IsEnabled = $false
            return
        }
        $def = Get-DefaultAdapter $script:adapters
        $ui.CmbAdapter.SelectedIndex = [array]::IndexOf($script:adapters, $def)
        if (-not $script:busy) { $ui.BtnRun.IsEnabled = $true }
    }

    function Show-AdapterInfo {
        $i = $ui.CmbAdapter.SelectedIndex
        $ui.AdapterFlags.Children.Clear()
        if ($script:adapters.Count -eq 0) { $ui.AdapterInfo.Text = T 'gui.noAdapters'; return }
        if ($i -lt 0 -or $i -ge $script:adapters.Count) { $ui.AdapterInfo.Text = ''; return }
        $a = $script:adapters[$i]
        $ui.AdapterInfo.Text = T 'gui.adapterInfo' $a.Description $a.IP $a.Prefix $a.Mask (Format-Value $a.Gateway) (Format-Value ($a.Dns -join ', ')) $a.Mac $a.LinkSpeed $a.Dhcp $a.Category
        if ($a.Wireless) { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.wifi') '#FFF1CC' '#8A5A00')) }
        else { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.cable') '#E3F6E8' '#126B2E')) }
        if ($a.Virtual) { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.virtual') '#FDE2E1' '#9B1C1C')) }
        if (-not $a.Gateway) { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.nogw') '#FDE2E1' '#9B1C1C')) }
        if ($a.IP -like '169.254.*') { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.apipa') '#FDE2E1' '#9B1C1C')) }
        if ($a.Category -eq 'Public') { [void]$ui.AdapterFlags.Children.Add((New-Chip (T 'chip.public') '#E6F0FB' '#1D4F91')) }
    }

    function Update-Counts {
        $ui.CntOk.Text = $script:counts.OK; $ui.CntWarn.Text = $script:counts.WARN
        $ui.CntFail.Text = $script:counts.FAIL; $ui.CntInfo.Text = $script:counts.INFO
        $ui.EmptyState.Visibility = if ($script:items.Count -gt 0) { 'Collapsed' } else { 'Visible' }
    }

    function Set-Verdict([string]$Title, [string]$Text, [string]$Bg, [string]$Border, [string]$Fg) {
        $ui.VerdictTitle.Text = $Title; $ui.VerdictText.Text = $Text
        $ui.VerdictCard.Background = $Bg; $ui.VerdictCard.BorderBrush = $Border; $ui.VerdictTitle.Foreground = $Fg
    }

    function Update-Verdict {
        if ($script:verdict -eq 'running') {
            Set-Verdict (T 'gui.running') (T 'gui.running.d') '#F3F8FD' '#C9DDF2' '#0B5FA5'
            return
        }
        if ($script:items.Count -eq 0) {
            Set-Verdict (T 'gui.noResults') (T 'gui.noResults.d') 'White' '#E1E5EA' '#0B2E59'
            return
        }
        $fails = @($script:items | Where-Object { $_.Status -eq 'FAIL' })
        $warns = @($script:items | Where-Object { $_.Status -eq 'WARN' })
        if ($fails.Count -gt 0) {
            $top = ($fails | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; '
            Set-Verdict (T 'gui.v.problems' $fails.Count) (T 'gui.v.top' $top) '#FFF5F5' '#F5C2C0' '#9B1C1C'
        } elseif ($warns.Count -gt 0) {
            $top = ($warns | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; '
            Set-Verdict (T 'gui.v.warns' $warns.Count) $top '#FFFBF0' '#F2D28B' '#8A5A00'
        } else {
            Set-Verdict (T 'gui.v.ok') (T 'gui.v.ok.d') '#F2FBF4' '#B9E3C4' '#126B2E'
        }
        if ($script:stopReq) { $ui.VerdictTitle.Text = T 'gui.stoppedPrefix' $ui.VerdictTitle.Text }
    }

    function Set-UiLanguage {
        # Elementy oznaczone Tag="L:klucz"
        $stack = New-Object System.Collections.Stack
        $stack.Push($window)
        while ($stack.Count -gt 0) {
            $el = $stack.Pop()
            if ($el -is [Windows.FrameworkElement] -and $el.Tag -is [string] -and $el.Tag.StartsWith('L:')) {
                $txt = T $el.Tag.Substring(2)
                if ($el -is [Windows.Controls.TextBlock]) { $el.Text = $txt }
                elseif ($el -is [Windows.Controls.ContentControl]) { $el.Content = $txt }
            }
            if ($el -is [Windows.DependencyObject]) {
                foreach ($ch in [Windows.LogicalTreeHelper]::GetChildren($el)) { if ($ch -is [Windows.DependencyObject]) { $stack.Push($ch) } }
            }
        }
        $ui.SubTitle.Text = T 'gui.subtitle' $script:Version
        $ui.AdminText.Text = if ($script:IsAdmin) { T 'gui.admin' } else { T 'gui.notadmin' }
        $ui.CmbLang.ToolTip = T 'gui.lang.tip'
        $ui.BtnRefresh.ToolTip = T 'gui.refresh.tip'
        $ui.BtnStatus.ToolTip = (T 'gui.statusPage.tip') + "`n" + $script:StatusPageUrl
        $ui.BtnAbout.ToolTip = T 'gui.about.tip'
        $ui.BtnElevate.ToolTip = (T 'gui.notadmin') + ". " + (T 'gui.elevate.tip')
        $ui.ChkFirewall.ToolTip = if ($script:IsAdmin) { $null } else { T 'gui.fw.tip' }
        # Czas nasłuchu
        $sel = [Math]::Max(0, $ui.CmbSeconds.SelectedIndex)
        $ui.CmbSeconds.Items.Clear()
        foreach ($opt in @(@(20, 'gui.sec20'), @(60, 'gui.sec60'), @(300, 'gui.sec300'), @(600, 'gui.sec600'))) {
            $ci = New-Object Windows.Controls.ComboBoxItem
            $ci.Content = T $opt[1]; $ci.Tag = $opt[0]
            [void]$ui.CmbSeconds.Items.Add($ci)
        }
        $ui.CmbSeconds.SelectedIndex = $sel
        Show-AdapterInfo
        Update-Verdict
        if (-not $script:busy) {
            $ls = $script:lastStatus
            $la = @($ls.Args)
            $ui.StatusText.Text = if ($la.Count -gt 0) { T $ls.Key @la } else { T $ls.Key }
        }
        $window.Title = 'SMA NetCheck'
    }

    function Add-UiResult($r) {
        $it = New-Object SmaNetCheck.ResultItem
        $it.Time = ([datetime]$r.Time).ToString('HH:mm:ss')
        $it.Category = $r.Category; $it.Name = $r.Name; $it.Status = $r.Status
        $it.StatusText = T "tag.$(([string]$r.Status).ToLower())"
        $it.Detail = $r.Detail; $it.Hint = $r.Hint
        $script:items.Add($it)
        [void]$script:Results.Add($r)      # kopia dla raportu HTML (Save-Report)
        $script:counts[[string]$r.Status]++
    }

    function Clear-Results {
        $script:items.Clear(); $script:Results.Clear()
        $script:counts = @{ OK = 0; WARN = 0; FAIL = 0; INFO = 0 }
        $script:stopReq = $false
        Update-Counts; Update-Verdict
    }

    function Set-Busy([bool]$Busy) {
        $script:busy = $Busy
        foreach ($c in 'BtnRun', 'CmbAdapter', 'BtnRefresh', 'ChkPortal', 'ChkScan', 'ChkMulticast', 'ChkDevices', 'TxtDevices', 'ChkRange', 'CmbSeconds', 'BtnClear', 'BtnElevate', 'CmbLang') { $ui[$c].IsEnabled = -not $Busy }
        $ui.ChkFirewall.IsEnabled = (-not $Busy) -and $script:IsAdmin
        $ui.TxtRange.IsEnabled = (-not $Busy) -and [bool]$ui.ChkRange.IsChecked
        $ui.BtnStop.IsEnabled = $Busy
        $ui.Progress.Visibility = if ($Busy) { 'Visible' } else { 'Hidden' }
        $window.Cursor = if ($Busy) { [Windows.Input.Cursors]::AppStarting } else { $null }
    }

    function Show-Msg([string]$Key, [string]$Icon = 'Warning') {
        [void][Windows.MessageBox]::Show((T $Key), 'SMA NetCheck', 'OK', $Icon)
    }

    function Start-Run {
        $i = $ui.CmbAdapter.SelectedIndex
        if ($i -lt 0) { Show-Msg 'gui.msg.selectAdapter'; return }
        $a = $script:adapters[$i]
        $devices = @()
        if ($ui.ChkDevices.IsChecked) { $devices = @($ui.TxtDevices.Text -split '[,;\s]+' | Where-Object { $_ }) }
        $opts = @{
            Index = $a.Index; IP = $a.IP; Lang = $script:Lang
            Portal = [bool]$ui.ChkPortal.IsChecked; Scan = [bool]$ui.ChkScan.IsChecked
            Multicast = [bool]$ui.ChkMulticast.IsChecked; Seconds = [int]$ui.CmbSeconds.SelectedItem.Tag
            Devices = $devices; Firewall = [bool]$ui.ChkFirewall.IsChecked
            Range = ''
        }
        # Własny zakres IP skanowania (opcjonalnie) - sprawdzany przed startem
        if ($opts.Scan -and $ui.ChkRange.IsChecked) {
            $rt = $ui.TxtRange.Text.Trim()
            if (-not $rt) { Show-Msg 'gui.msg.enterRange'; $ui.TxtRange.Focus(); return }
            $rc = Get-IpRangeList $rt
            if (-not $rc.Ok) {
                [void][Windows.MessageBox]::Show(($rc.Error + "`n`n" + (T 'range.examples')), 'SMA NetCheck', 'OK', 'Warning')
                $ui.TxtRange.Focus(); return
            }
            $opts.Range = $rt
        }
        if ($ui.ChkDevices.IsChecked -and $devices.Count -eq 0) { Show-Msg 'gui.msg.enterDevice'; return }
        if (-not ($opts.Portal -or $opts.Scan -or $opts.Multicast -or $devices.Count -gt 0)) { Show-Msg 'gui.msg.selectTest'; return }
        Clear-Results
        $script:AllAdapters = @(Get-AdapterList)
        $script:Adapter = $a
        $bgSync.Status = T 'gui.starting'; $bgSync.Progress = -1
        $script:runStart = Get-Date
        $script:verdict = 'running'
        Update-Verdict
        $script:ps = [powershell]::Create()
        $script:ps.Runspace = $bgRs
        [void]$script:ps.AddScript($runScript).AddArgument($opts)
        $script:handle = $script:ps.BeginInvoke()
        Set-Busy $true
    }

    function Complete-Run {
        $o = $null
        while ($bgSync.Queue.TryDequeue([ref]$o)) { Add-UiResult $o }
        try { [void]$script:ps.EndInvoke($script:handle) }
        catch {
            if (-not $script:stopReq) {
                Add-UiResult ([pscustomobject]@{ Time = Get-Date; Category = (T 'cat.program'); Name = (T 'gui.err.run'); Status = 'WARN'; Detail = $_.Exception.InnerException.Message; Hint = '' })
            }
        }
        foreach ($e in @($script:ps.Streams.Error | Select-Object -First 5)) {
            Add-UiResult ([pscustomobject]@{ Time = Get-Date; Category = (T 'cat.program'); Name = (T 'gui.err.script'); Status = 'INFO'; Detail = $e.ToString(); Hint = '' })
        }
        $script:ps.Dispose(); $script:ps = $null
        if ($script:stopReq) {
            # Upewnij się, że reguła zapory nie została
            $c = [powershell]::Create(); $c.Runspace = $bgRs
            try { [void]$c.AddScript('Remove-TempFirewallRule').Invoke() } catch { } finally { $c.Dispose() }
        }
        Set-Busy $false
        $dur = [int]((Get-Date) - $script:runStart).TotalSeconds
        if ($script:stopReq) { Set-StatusKey 'gui.stopped' $dur } else { Set-StatusKey 'gui.done' $dur }
        $script:verdict = 'done'
        Update-Counts; Update-Verdict
    }

    function Invoke-Tick {
        $o = $null
        $added = $false
        while ($bgSync.Queue.TryDequeue([ref]$o)) { Add-UiResult $o; $added = $true }
        if ($added) { Update-Counts; $ui.LstResults.ScrollIntoView($script:items[$script:items.Count - 1]) }
        if ($script:busy) {
            if ($bgSync.Status) { $ui.StatusText.Text = $bgSync.Status }
            if ($bgSync.Progress -ge 0) { $ui.Progress.IsIndeterminate = $false; $ui.Progress.Value = $bgSync.Progress }
            else { $ui.Progress.IsIndeterminate = $true }
            if ($script:handle -and $script:handle.IsCompleted) { Complete-Run }
        }
    }

    function Get-ResultsText {
        $sb = New-Object Text.StringBuilder
        $a = $script:Adapter
        [void]$sb.AppendLine("SMA NetCheck $($script:Version) - $(Get-Date -Format 'yyyy-MM-dd HH:mm') - $env:COMPUTERNAME")
        if ($a) { [void]$sb.AppendLine((T 'gui.copy.adapter' $a.Alias $a.IP $a.Prefix (Format-Value $a.Gateway) (Format-Value ($a.Dns -join ', ')))) }
        [void]$sb.AppendLine((T 'gui.copy.counts' $script:counts.OK $script:counts.WARN $script:counts.FAIL))
        foreach ($g in ($script:items | Group-Object Category)) {
            [void]$sb.AppendLine(''); [void]$sb.AppendLine("== $($g.Name) ==")
            foreach ($r in $g.Group) {
                [void]$sb.AppendLine(("[{0}] {1}{2}" -f $r.StatusText, $r.Name, $(if ($r.Detail) { " - $($r.Detail)" } else { '' })))
                if ($r.Hint) { foreach ($l in ($r.Hint -split "`n")) { [void]$sb.AppendLine("      -> $l") } }
            }
        }
        return $sb.ToString()
    }

    # =================================================================================
    #  ZDARZENIA
    # =================================================================================
    foreach ($code in $script:LangCodes) {
        $ci = New-Object Windows.Controls.ComboBoxItem
        $ci.Content = "$code - $($script:langNames[$code])"; $ci.Tag = $code
        [void]$ui.CmbLang.Items.Add($ci)
    }
    $ui.CmbLang.SelectedIndex = $script:LangIndex

    if ($script:IsAdmin) {
        $ui.BtnElevate.Visibility = 'Collapsed'
        $ui.ChkFirewall.IsChecked = $true
    } else {
        # Bez uprawnień: zamiast szarej plakietki wystarczy przycisk "Uruchom jako administrator"
        $ui.AdminBadge.Visibility = 'Collapsed'
        $ui.ChkFirewall.IsEnabled = $false
    }

    $ui.CmbLang.Add_SelectionChanged({
        $code = [string]$ui.CmbLang.SelectedItem.Tag
        if (-not $code -or $code -eq $script:Lang) { return }
        Set-NcLanguage $code
        [void](Save-NcLanguage $code)
        Set-UiLanguage
        if ($script:items.Count -gt 0) { Set-StatusKey 'gui.langNote' }
    })
    $ui.CmbAdapter.Add_SelectionChanged({ Show-AdapterInfo })
    $ui.BtnRefresh.Add_Click({ Update-Adapters; Show-AdapterInfo })
    $ui.ChkDevices.Add_Checked({ $ui.TxtDevices.Focus() })
    $ui.ChkRange.Add_Checked({ $ui.TxtRange.IsEnabled = $true; $ui.ChkScan.IsChecked = $true; [void]$ui.TxtRange.Focus() })
    $ui.ChkRange.Add_Unchecked({ $ui.TxtRange.IsEnabled = $false })
    $ui.TxtDevices.Add_TextChanged({ if ($ui.TxtDevices.Text.Trim()) { $ui.ChkDevices.IsChecked = $true } })
    $ui.BtnRun.Add_Click({ Start-Run })
    $ui.BtnStatus.Add_Click({ try { Start-Process $script:StatusPageUrl } catch { } })
    $ui.BtnAbout.Add_Click({
        # README.txt leży obok Start-SMA-NetCheck.cmd (folder nad "app"); gdy go brak - README na GitHub
        $readme = @((Join-Path (Split-Path $PSScriptRoot -Parent) 'README.txt'), (Join-Path $PSScriptRoot 'README.txt')) | Where-Object { Test-Path $_ } | Select-Object -First 1
        try {
            if ($readme) { Start-Process -FilePath $readme } else { Start-Process 'https://github.com/Nightry/SMA-NetCheck#readme' }
        } catch {
            try { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$readme`"" } catch { }
        }
    })
    $ui.BtnStop.Add_Click({
        if ($script:ps) {
            $script:stopReq = $true
            $ui.StatusText.Text = T 'gui.stopping'
            [void]$script:ps.BeginStop($null, $null)
        }
    })
    $ui.BtnClear.Add_Click({ $script:verdict = 'none'; Clear-Results; Set-StatusKey 'gui.ready' })
    $ui.ChkOnlyProblems.Add_Click({
        if ($ui.ChkOnlyProblems.IsChecked) { $view.Filter = [Predicate[object]] { param($x) $x.Status -eq 'FAIL' -or $x.Status -eq 'WARN' } }
        else { $view.Filter = $null }
    })
    $ui.BtnCopy.Add_Click({
        if ($script:items.Count -eq 0) { return }
        [Windows.Clipboard]::SetText((Get-ResultsText))
        Set-StatusKey 'gui.copied'
    })
    $ui.BtnReport.Add_Click({
        if ($script:Results.Count -eq 0) { Show-Msg 'gui.report.none' 'Information'; return }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = T 'gui.report.filter'
        $dlg.FileName = "SMA-NetCheck_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html"
        $def = $script:ReportsDir
        if (-not (Test-Path $def)) { try { New-Item -ItemType Directory -Path $def -ErrorAction Stop | Out-Null } catch { $def = [Environment]::GetFolderPath('Desktop') } }
        $dlg.InitialDirectory = $def
        if ($dlg.ShowDialog($window)) {
            $p = Save-Report $dlg.FileName
            if ($p) {
                Set-StatusKey 'gui.report.saved' $p
                $ans = [Windows.MessageBox]::Show((T 'gui.report.open' $p), 'SMA NetCheck', 'YesNo', 'Information')
                if ($ans -eq 'Yes') { Start-Process $p }
            } else {
                Show-Msg 'gui.report.fail' 'Error'
            }
        }
    })
    $ui.BtnElevate.Add_Click({
        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`""
            $window.Close()
        } catch { }
    })

    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({ Invoke-Tick })

    $window.Add_Closing({
        param($s, $e)
        if ($script:busy) {
            $ans = [Windows.MessageBox]::Show((T 'gui.closeConfirm'), 'SMA NetCheck', 'YesNo', 'Question')
            if ($ans -ne 'Yes') { $e.Cancel = $true; return }
            try { $script:ps.Stop() } catch { }
            $c = [powershell]::Create(); $c.Runspace = $bgRs
            try { [void]$c.AddScript('Remove-TempFirewallRule').Invoke() } catch { } finally { $c.Dispose() }
        }
        $timer.Stop()
    })

    $window.Add_ContentRendered({
        [void](Clear-LeftoverFirewallRule)   # sprzątanie po ewentualnym przerwanym teście
        Update-Adapters
        Set-UiLanguage
        Update-Counts
        $timer.Start()
    })

    [void]$window.ShowDialog()
    try { $bgRs.Close(); $bgRs.Dispose() } catch { }
}
catch {
    $title = 'SMA NetCheck'
    $head = 'Could not start SMA NetCheck:'
    try { $head = T 'gui.startFail' } catch { }
    $msg = "$head`n`n$($_.Exception.Message)`n`n$($_.InvocationInfo.PositionMessage)"
    try { [void][System.Windows.MessageBox]::Show($msg, $title, 'OK', 'Error') }
    catch { Write-Host $msg -ForegroundColor Red }
}
